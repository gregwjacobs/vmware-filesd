import atexit
import ssl
import json

import requests
from pyVim import connect
from pyVmomi import vim, vmodl
from argparse import ArgumentParser
import os 

from com.vmware.vapi.std_client import DynamicID
from vmware.vapi.vsphere.client import create_vsphere_client


class HostList:
    def __init__(self, output_filename):
        self.hosts = []
        self.output_filename = output_filename

    def add_host(self, host):
        if not self.host_exists(host.hostname):
            self.hosts.append(host)

    def host_exists(self, uuid):
        for host in self.hosts:
            if host.uuid == uuid:
                return True
        return False

    def prometheus_output(self):
        output = []
        for host in self.hosts:
            x = {
                "targets": [host.hostname],
                "labels" : host.tags
            }
            output.append(x)

        if os.path.exists(self.output_filename):
                os.remove(self.output_filename)

        with open(self.output_filename, 'w') as f:
            json.dump(output, f)


class Host:
    def __init__(self, uuid, hostname, ip_address):
        self.hostname = hostname
        self.ip_address = ip_address
        self.uuid = uuid
        self.tags = {}
        self.tags["address"] = ip_address
        self.tags["uuid"] = uuid

    def add_values(self, key, value):
        print(f"Adding value to {self.hostname} key: {key} value: {value}")
        self.tags[key] = value

    def get_hostname(self):
        return self.hostname


class VMwareInventory:
    def __init__(self, hostname, username, password, port, output_filename, validate_certs, with_tags):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.with_tags = with_tags
        self.validate_certs = validate_certs
        self.content = None
        self.rest_content = None
        self.hostlist = HostList(output_filename)

    def _login(self):
        """
        Login to vCenter or ESXi server
        Returns: connection object

        """
        if self.validate_certs and not hasattr(ssl, 'SSLContext'):
            raise Exception('pyVim does not support changing verification mode with python < 2.7.9. Either update '
                            'python or set validate_certs to false in configuration YAML file.')

        ssl_context = None
        if not self.validate_certs and hasattr(ssl, 'SSLContext'):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.verify_mode = ssl.CERT_NONE

        service_instance = None
        try:
            service_instance = connect.SmartConnect(host=self.hostname, user=self.username,
                                                    pwd=self.password, sslContext=ssl_context,
                                                    port=self.port)
        except vim.fault.InvalidLogin as e:
            raise Exception("Unable to log on to vCenter or ESXi API at %s:%s as %s: %s" % (
                self.hostname, self.port, self.username, e.msg))
        except vim.fault.NoPermission as e:
            raise Exception("User %s does not have required permission"
                            " to log on to vCenter or ESXi API at %s:%s : %s" % (self.username, self.hostname, self.port, e.msg))
        except (requests.ConnectionError, ssl.SSLError) as e:
            raise Exception("Unable to connect to vCenter or ESXi API at %s on TCP/%s: %s" %
                            (self.hostname, self.port, e))
        except vmodl.fault.InvalidRequest as e:
            # Request is malformed
            raise Exception("Failed to get a response from server %s:%s as "
                            "request is malformed: %s" % (self.hostname, self.port, e.msg))
        except Exception as e:
            raise Exception("Unknown error while connecting to vCenter or ESXi API at %s:%s : %s" % (
                self.hostname, self.port, e))

        if service_instance is None:
            raise Exception("Unknown error while connecting to vCenter or ESXi API at %s:%s" % (
                self.hostname, self.port))

        atexit.register(connect.Disconnect, service_instance)
        return service_instance.RetrieveContent()

    def do_login(self):
        """
        Check requirements and do login
        """
        self.content = self._login()
        if self.with_tags:
            self.rest_content = self._login_vapi()

    def _login_vapi(self):
        """
        Login to vCenter API using REST call
        Returns: connection object

        """
        session = requests.Session()
        session.verify = self.validate_certs
        if not self.validate_certs:
            # Disable warning shown at stdout
            requests.packages.urllib3.disable_warnings()

        print("logging in")
        client = create_vsphere_client(server=self.hostname,
                                       username=self.username,
                                       password=self.password,
                                       session=session)
        if client is None:
            raise Exception("Failed to login to %s using %s" %
                            (self.hostname, self.username))
        return client

    def _get_managed_objects_properties(self, vim_type, properties=None):
        """
        Look up a Managed Object Reference in vCenter / ESXi Environment
        :param vim_type: Type of vim object e.g, for datacenter - vim.Datacenter
        :param properties: List of properties related to vim object e.g. Name
        :return: local content object
        """
        # Get Root Folder
        root_folder = self.content.rootFolder

        if properties is None:
            properties = ['name']

        # Create Container View with default root folder
        mor = self.content.viewManager.CreateContainerView(
            root_folder, [vim_type], True)

        # Create Traversal spec
        traversal_spec = vmodl.query.PropertyCollector.TraversalSpec(
            name="traversal_spec",
            path='view',
            skip=False,
            type=vim.view.ContainerView
        )

        # Create Property Spec
        property_spec = vmodl.query.PropertyCollector.PropertySpec(
            type=vim_type,  # Type of object to retrieved
            all=False,
            pathSet=properties
        )

        # Create Object Spec
        object_spec = vmodl.query.PropertyCollector.ObjectSpec(
            obj=mor,
            skip=True,
            selectSet=[traversal_spec]
        )

        # Create Filter Spec
        filter_spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[object_spec],
            propSet=[property_spec],
            reportMissingObjectsInResults=False
        )

        return self.content.propertyCollector.RetrieveContents([filter_spec])

    def _get_object_prop(self, vm, attributes):
        """Safely get a property or return None"""
        result = vm
        for attribute in attributes:
            try:
                result = getattr(result, attribute)
            except (AttributeError, IndexError):
                return None
        return result

    def populate(self):

        objects = self._get_managed_objects_properties(vim_type=vim.VirtualMachine,
                                                       properties=['name'])
        tag_svc = self.rest_content.tagging.Tag
        tag_association = self.rest_content.tagging.TagAssociation
        cat_svc = self.rest_content.tagging.Category

        # Get tags and categories to lower amount of api requests needed
        cat_info = dict()
        tags_info = dict()
        tags = tag_svc.list()
        cats = cat_svc.list()

        for cat in cats:
            cat_obj = cat_svc.get(cat)
            cat_info[cat_obj.id] = cat_obj.name
        for tag in tags:
            tag_obj = tag_svc.get(tag)
            tags_info[tag_obj.id] = dict(name=tag_obj.name,category=cat_info[tag_obj.category_id])

        for vm_obj in objects:
            for vm_obj_property in vm_obj.propSet:
                # VMware does not provide a way to uniquely identify VM by its name
                # i.e. there can be two virtual machines with same name
                # Appending "_" and VMware UUID to make it unique
                if not vm_obj.obj.config:
                    # Sometime orphaned VMs return no configurations
                    continue

                if not self.hostlist.host_exists(vm_obj.obj.config.uuid):
                    vm_mo_id = vm_obj.obj._GetMoId()
                    vm_dynamic_id = DynamicID(
                        type='VirtualMachine', id=vm_mo_id)
                    attached_tags = tag_association.list_attached_tags(
                        vm_dynamic_id)
                    
                    if not vm_obj.obj.guest or not vm_obj.obj.guest.ipAddress:
                        continue
                    
                    host_ip = vm_obj.obj.guest.ipAddress
                    if host_ip is None:
                        continue

                    current_host = Host(
                        vm_obj.obj.config.uuid, vm_obj_property.val, host_ip)

                    for tag_id in attached_tags:
                        current_host.add_values(tags_info[tag_id]['category'], tags_info[tag_id]['name'])

                    self.hostlist.add_host(current_host)
        return


def main():
    parser = ArgumentParser()
    parser.add_argument("-o", "--hostname", dest="hostname",
                        help="vsphere hostname")
    parser.add_argument("-u", "--username",
                        dest="username",
                        help="vsphere username")
    parser.add_argument("-p", "--password",
                        dest="password",
                        help="vsphere password")
    parser.add_argument("-f", "--file", dest="filename",
                        help="write report to FILE", metavar="FILE")
    parser.add_argument("-l", "--loop", dest="loop",
                        help="loop over and over", action='store_true')

    args = parser.parse_args()

    while True:
        vmware = VMwareInventory(args.hostname, args.username, args.password, "443", args.filename, False, True)
        vmware.do_login()
        vmware.populate()
        vmware.hostlist.prometheus_output()
        if args.loop == False:
            break

if __name__ == '__main__':
    main()