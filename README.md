[comment]: # "Auto-generated SOAR connector documentation"
# Windows Remote Management

Publisher: Splunk  
Connector Version: 2.2.7  
Product Vendor: Microsoft  
Product Name: Windows Remote Management  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.1  

This app integrates with the Windows Remote Management service to execute various actions

[comment]: # ""
[comment]: # "    File: README.md"
[comment]: # "    Copyright (c) 2018-2024 Splunk Inc."
[comment]: # "    "
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
[comment]: # ""
Without additional configuration on the proxy server, it will not be possible to connect to WinRM
using NTLM authentication through an HTTP(S) proxy. If authentication is set to basic, then it will
still work, however.

To use the proxy settings you need to add the proxy server as an environment variable. You can add
an environment variable using the below command.

-   For Linux/Mac: `      export HTTP_PROXY="http://<proxy server>:<proxy port>/"     `
-   For Windows powershell: `      $env:HTTP_PROXY="http://<proxy server>:<proxy port>/"     `

If the user tries to add any invalid proxy URL, the proxy will be bypassed and won't affect the
app's connectivity.

To use this app you must have the Windows Remote Management service running on the endpoint you wish
to connect to. For help regarding this process, consult this link:
<https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx>

WinRM Ports Requirements (Based on Standard Guidelines of [IANA
ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

-   WinRM(service) TCP(transport layer protocol) port for Windows Remote Management Service - 47001

The protocol and port can be specified with the IP/hostname. For example, if using HTTPS on port
5986, the IP/Hostname should be **https://192.168.10.21:5986** .

In the configuration options for the asset, a default protocol and port for actions can be
specified. These options will be prepended or appended to the IP/hostname provided for all actions
including **test connectivity** . If a different protocol or port number is specified in the
IP/hostname field, the corresponding default will be ignored.

This app supports adding a custom parser for the actions **run script** and **run command** . By
default, the output of these actions will just be the status code, standard out, and standard error
of whatever gets ran. If you want to capture a specific string or fail on a certain status code, you
will need to provide a custom parser.

The custom parser should be a file added to the vault containing a function named **custom_parser**
.

``` shell
        
        import phantom.app as phantom


        def custom_parser(action_result, response):
            # type: (ActionResult, winrm.Response) -> bool
            data = {}
            data['status_code'] = response.status_code
            data['std_out'] = response.std_out
            data['std_err'] = response.std_err

            action_result.add_data(data)
            return phantom.APP_SUCCESS
        
        
```

This is equivalent to the default parser which is used if nothing is provided. It takes in an
ActionResult and a Response object (from the pywinrm module), and it is expected to return a boolean
value (phantom.APP_SUCCESS and phantom.APP_ERROR are equivalent to True and False).

Here is an example of a parser that will extract all the IPs from the output, and fail if there is a
non-zero status code.

``` shell
        
        import re
        import phantom.app as phantom
        from phantom import utils as ph_utils


        def custom_parser(action_result, response):
            # type: (ActionResult, winrm.Response) -> bool
            data = {}
            data['status_code'] = response.status_code
            data['std_out'] = response.std_out
            data['std_err'] = response.std_err

            if data['status_code'] != 0:
                # This will be the message displayed
                action_result.add_data(data)
                return action_result.set_status(
                    phantom.APP_ERROR, "Error: Returned a non-zero status code"
                )

            # This can still return values like 999.999.999.999
            ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data['std_out'])
            # Get only valid IPs
            filtered_ips = []
            for ip in ips:
                if ph_utils.is_ip(ip):
                    filtered_ips.append(ip)

            data['ips'] = filtered_ips

            action_result.add_data(data)
            return phantom.APP_SUCCESS
        
        
```

As a final thing to consider, the playbook editor will not be aware of any custom data paths which
your parser introduces. Using the above example, if you wanted to use the list of ips in a playbook,
you would need to type in the correct datapath manually (action_result.data.\*.ips).

For more information on datapaths and the ActionResult object, refer to the Phantom App Developer
Guide.

Both the **run script** and **run command** actions also support running commands asynchronously. By
default, the app will wait for these actions to finish. In the case of starting a long-running job
or some other command which you want to start but don't care for the output, then you can check the
**async** parameter. After the command starts, it will return a **command_id** and **shell_id** ,
which you can optionally use to retrieve the output of that command at a later time.

### Certificate Authentication

To authenticate using SSL certificates, select `certificate` authentication in asset configuration method and pass following configuration parameters.

* cert_pem_path - A path to signed certificate file that is trusted by the Windows instance, in PEM format

* cert_key_pem_path - A filepath to key used to generate cert_pem file

* ca_trust_path - The certificate of the certificate authority that signed cert_file. It's needed only when you set up your own certificate authority.

It is recommended that these files be placed under the <PHANTOM_HOME>/etc/ssl/ directory. These files must be readable by the phantom-worker user.

### Kerberos Authentication

To authenticate using Kerberos, select `kerberos` authentication in asset configuration and provide hostname and username used for authorization.
You'll also need to setup your instance to support Kerberos:

-  Kerberos packages have to be installed:
    - for Debian/Ubuntu/etc: `sudo apt-get install krb5-user`
    - for RHEL/CentOS/etc: `sudo yum install krb5-workstation krb5-libs krb5-auth-dialog`

-  `/etc/krb5.conf` needs to be properly configured for your realm and kdc
-  If there is no DNS configuration, `hosts` file will need to have mappings for server with mssccm under same domain as on Windows server 
-  `kinit` must be run for principal that will be used to connect to msccm
-   It should be noted that Kerberos tickets will expire, so it is recommended to use a script to
    run `kinit` periodically to refresh the ticket for the user, alternatively `keytab` file can be created on server and used on client for connectivity.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Windows Remote Management asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**endpoint** |  optional  | string | IP/Hostname (For TEST CONNECTIVITY and default, if not provided in an action)
**verify_server_cert** |  optional  | boolean | Verify Server Certificate
**default_protocol** |  optional  | string | Default protocol for actions
**default_port** |  optional  | numeric | Default port for actions
**domain** |  optional  | string | Domain
**username** |  required  | string | Username
**password** |  required  | password | Password
**transport** |  required  | string | Type of transport to use
**cert_pem_path** |  optional  | string | Path to SSL certificate PEM file
**cert_key_pem_path** |  optional  | string | Path to SSL key file
**ca_trust_path** |  optional  | string | Path to trusted CRT file

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[run command](#action-run-command) - Execute a command on the endpoint  
[run script](#action-run-script) - Run a PowerShell script on the endpoint  
[list processes](#action-list-processes) - List the currently running processes  
[terminate process](#action-terminate-process) - Terminate a process  
[list connections](#action-list-connections) - List all active connections  
[list firewall rules](#action-list-firewall-rules) - List the firewall rules  
[delete firewall rule](#action-delete-firewall-rule) - Remove a firewall rule using netsh  
[block ip](#action-block-ip) - Create a firewall rule to block a specified IP  
[add firewall rule](#action-add-firewall-rule) - Add a firewall rule using netsh  
[logoff user](#action-logoff-user) - Logoff a user  
[list sessions](#action-list-sessions) - List all active sessions  
[deactivate partition](#action-deactivate-partition) - Deactivate a partition  
[activate partition](#action-activate-partition) - Activate a partition  
[shutdown system](#action-shutdown-system) - Shutdown a system  
[restart system](#action-restart-system) - Restart a system  
[list policies](#action-list-policies) - List AppLocker Policies  
[block file path](#action-block-file-path) - Create a new AppLocker policy to block a file path  
[delete policy](#action-delete-policy) - Delete an AppLocker policy  
[get file](#action-get-file) - Copy a file from the Windows Endpoint to the Vault  
[upload file](#action-upload-file) - Copy a file from the vault to the Windows Endpoint  
[copy file](#action-copy-file) - Run the copy command on the Windows Endpoint  
[delete file](#action-delete-file) - Run the delete command on the Windows Endpoint  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'run command'
Execute a command on the endpoint

Type: **generic**  
Read only: **False**

Unless you implement a custom parser, this action will always succeed regardless of the input. Either a <b>command</b> or pair of <b>command_id</b> and <b>shell_id</b> must be specified. If a <b>command_id</b> is present, all other parameters will be ignored. <p><b>Note:</b> The command_id and shell_id you provide to fetch the output can only be used once because once the output is fetched successfully server will remove output from its cache.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**command** |  optional  | The command to be run | string | 
**arguments** |  optional  | The arguments for the command | string | 
**parser** |  optional  | The vault ID of a custom parser to use for output | string |  `vault id` 
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**async** |  optional  | Start the command, but don't wait for output | boolean | 
**command_id** |  optional  | Command ID of async command (Provide with shell_id) | string |  `winrm command id` 
**shell_id** |  optional  | Shell ID of async command (Provide with command_id) | string |  `winrm shell id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.arguments | string |  |   /all 
action_result.parameter.async | boolean |  |   True  False 
action_result.parameter.command | string |  |   ipconfig 
action_result.parameter.command_id | string |  `winrm command id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.parser | string |  `vault id`  |   8afa5c86de9ea94ecfe5b4c0837d2543d0b20b56 
action_result.parameter.shell_id | string |  `winrm shell id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
action_result.data.\*.status_code | numeric |  |   0 
action_result.data.\*.std_err | string |  |   Error message 
action_result.data.\*.std_out | string |  |   Successful output 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully ran command 
action_result.summary | string |  |  
action_result.summary.command_id | string |  `winrm command id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
action_result.summary.shell_id | string |  `winrm shell id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'run script'
Run a PowerShell script on the endpoint

Type: **generic**  
Read only: **False**

The script you provide can either be in the vault, or it can just be a string of the script to run. If both values are present, it will use the <b>script_file</b> over the <b>script_str</b>. Unless you implement a custom parser, this action will always succeed regardless of the input. If <b>command_id</b> and <b>shell_id</b> are present, <b>script_file</b> and <b>script_str</b> will be ignored. This action will fail if at least one of <b>script_file</b>, <b>script_str</b>, or the pair of <b>command_id</b> and <b>shell_id</b> are not specified. <p><b>Note:</b> The command_id and shell_id you provide to fetch the output can only be used once because once the output is fetched successfully server will remove output from its cache.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**script_file** |  optional  | The vault ID of a PowerShell script to run | string |  `vault id` 
**script_str** |  optional  | A PowerShell script to run | string | 
**parser** |  optional  | The vault ID of a custom parser to use for output | string |  `vault id` 
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**async** |  optional  | Start the command, but don't wait for output | boolean | 
**command_id** |  optional  | Command ID of async command (Provide with shell_id) | string |  `winrm command id` 
**shell_id** |  optional  | Shell ID of async command (Provide with command_id) | string |  `winrm shell id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.async | boolean |  |   True  False 
action_result.parameter.command_id | string |  `winrm command id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.parser | string |  `vault id`  |   8afa5c86de9ea94ecfe5b4c0837d2543d0b20b56 
action_result.parameter.script_file | string |  `vault id`  |   8afa5c86de9ea94ecfe5b4c0837d2543d0b20b56 
action_result.parameter.script_str | string |  |   Write-Host Hello 
action_result.parameter.shell_id | string |  `winrm shell id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
action_result.data.\*.status_code | numeric |  |   0 
action_result.data.\*.std_err | string |  |   Error message 
action_result.data.\*.std_out | string |  |   Successful output 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully ran PowerShell script 
action_result.summary | string |  |  
action_result.summary.command_id | string |  `winrm command id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
action_result.summary.shell_id | string |  `winrm shell id`  |   1AAA1111-1A11-11A1-1111-1A1AAA1A11A1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list processes'
List the currently running processes

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data.\*.handles | numeric |  |   33 
action_result.data.\*.name | string |  `process name`  |   cmd 
action_result.data.\*.non_paged_memory | numeric |  |   3 
action_result.data.\*.paged_memory | numeric |  |   1564 
action_result.data.\*.pid | numeric |  `pid`  |   3108 
action_result.data.\*.processor_time_(s) | numeric |  |   0.02 
action_result.data.\*.virtual_memory | numeric |  |   14 
action_result.data.\*.working_set | numeric |  |   2384 
action_result.data.\*.session_id | numeric |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully got process list 
action_result.summary | string |  |  
action_result.summary.num_processes | numeric |  |   451 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'terminate process'
Terminate a process

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pid** |  optional  | The PID of the process to terminate | numeric |  `pid` 
**name** |  optional  | Name of program to terminate, accepts wildcards | string |  `process name` 
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.name | string |  `process name`  |   iexplore 
action_result.parameter.pid | numeric |  `pid`  |   451 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully terminated process 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list connections'
List all active connections

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data.\*.foreign_address_ip | string |  `ip`  |   8.8.8.8 
action_result.data.\*.foreign_address_port | string |  `port`  |   11100 
action_result.data.\*.local_address_ip | string |  `ip`  |   8.8.8.8 
action_result.data.\*.local_address_port | string |  `port`  |   11100 
action_result.data.\*.pid | numeric |  `pid`  |   451 
action_result.data.\*.protocol | string |  |   TCP 
action_result.data.\*.state | string |  |   ESTABLISHED 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully listed connections 
action_result.summary | string |  |  
action_result.summary.num_connections | numeric |  |   451 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list firewall rules'
List the firewall rules

Type: **investigate**  
Read only: **True**

When you are using the <b>other</b> parameter, you can match for any field which is returned in the action result. It will only return a rule if it matches all of the criteria, not if it matches at least one.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter_port** |  optional  | Only show firewall rules acting on this port | string |  `port` 
**filter_ip** |  optional  | Only show firewall rules acting on this ip | string |  `ip` 
**direction** |  optional  | Only show firewall rules in this direction | string | 
**protocol** |  optional  | Only show firewall rules using this protocol | string |  `winrm protocol` 
**other** |  optional  | JSON object of key value pairs of other fields to match | string | 
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.direction | string |  |   in 
action_result.parameter.filter_ip | string |  `ip`  |   8.8.8.8 
action_result.parameter.filter_port | string |  `port`  |   11100 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.other | string |  |   {"enabled": "yes"} 
action_result.parameter.protocol | string |  `winrm protocol`  |   tcp 
action_result.data.\*.action | string |  |   allow 
action_result.data.\*.direction | string |  |   in 
action_result.data.\*.edge_traversal | string |  |   no 
action_result.data.\*.enabled | string |  |   yes 
action_result.data.\*.grouping | string |  |   windows remote management 
action_result.data.\*.local_ip | string |  `ip`  |   any 
action_result.data.\*.local_port | string |  `port`  |   5985 
action_result.data.\*.profiles | string |  |   domain,private 
action_result.data.\*.protocol | string |  `winrm protocol`  |   tcp 
action_result.data.\*.remote_ip | string |  `ip`  |   any 
action_result.data.\*.remote_port | string |  `port`  |   any 
action_result.data.\*.rule_name | string |  `windows firewall rule name`  |   windows remote management (http-in) 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully retrieved firewall rules 
action_result.summary | string |  |  
action_result.summary.num_rules | numeric |  |   451 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete firewall rule'
Remove a firewall rule using netsh

Type: **generic**  
Read only: **False**

This action will invoke the command <code>netsh advfirewall firewall delete rule</code>, and the rest is determined by the input. At a minimum, the rule name must be provided, but if you need to you can also specify any other arguments which the command accepts, in the same manner, that input from the <b>add firewall rule</b> gets added.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | The name of the rule to remove | string |  `windows firewall rule name` 
**dir** |  optional  | Blocks inbound or outbound traffic | string | 
**remote_ip** |  optional  | Firewall rule acts on this remote IP | string |  `ip` 
**local_ip** |  optional  | Firewall rule acts on this local IP | string |  `ip` 
**remote_port** |  optional  | Firewall rule acts on this remote port | string |  `port` 
**local_port** |  optional  | Firewall rule acts on this local port | string |  `port` 
**protocol** |  optional  | Firewall rule acts on this protocol | string |  `winrm protocol` 
**other** |  optional  | JSON object of key value pairs for other parameters to include | string | 
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.dir | string |  |   in  out 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.local_ip | string |  `ip`  |   8.8.8.8 
action_result.parameter.local_port | string |  `port`  |   443 
action_result.parameter.name | string |  `windows firewall rule name`  |   test rule 
action_result.parameter.other | string |  |   {"profile": "domain"} 
action_result.parameter.protocol | string |  `winrm protocol`  |   any  tcp 
action_result.parameter.remote_ip | string |  `ip`  |   8.8.8.8 
action_result.parameter.remote_port | string |  `port`  |   443 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully deleted firewall rules 
action_result.summary | string |  |  
action_result.summary.rules_deleted | numeric |  |   2 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'block ip'
Create a firewall rule to block a specified IP

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**name** |  required  | The name of the rule to add | string |  `windows firewall rule name` 
**remote_ip** |  required  | Block this IP | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.name | string |  `windows firewall rule name`  |   test rule 
action_result.parameter.remote_ip | string |  `ip`  |   8.8.8.8 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully created firewall rule 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'add firewall rule'
Add a firewall rule using netsh

Type: **generic**  
Read only: **False**

This action will invoke the command <code>netsh advfirewall firewall add rule</code>, where the rest is determined by the input. Each <b>key-value</b> pair from the <b>other</b> parameter will be added in the form of <b>key</b>=<b>value</b>. The user input will  be sanitized.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | The name of the rule to add | string |  `windows firewall rule name` 
**dir** |  required  | Block inbound or outbound traffic | string | 
**action** |  required  | What the firewall will do with packets | string | 
**remote_ip** |  optional  | Firewall rule acts on this remote IP | string |  `ip` 
**local_ip** |  optional  | Firewall rule acts on this local IP | string |  `ip` 
**remote_port** |  optional  | Firewall rule acts on this remote port | string |  `port` 
**local_port** |  optional  | Firewall rule acts on this local port | string |  `port` 
**protocol** |  optional  | Firewall rule acts on this protocol | string |  `winrm protocol` 
**other** |  optional  | JSON object of key value pairs for other parameters to include | string | 
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.action | string |  |   block 
action_result.parameter.dir | string |  |   in  out 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.local_ip | string |  `ip`  |   8.8.8.8 
action_result.parameter.local_port | string |  `port`  |   443 
action_result.parameter.name | string |  `windows firewall rule name`  |   test rule 
action_result.parameter.other | string |  |   {"profile": "domain"} 
action_result.parameter.protocol | string |  `winrm protocol`  |   any  tcp 
action_result.parameter.remote_ip | string |  `ip`  |   8.8.8.8 
action_result.parameter.remote_port | string |  `port`  |   443 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully created firewall rule 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'logoff user'
Logoff a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**session_id** |  required  | Session ID | string |  `windows session id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.session_id | string |  `windows session id`  |   2 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully logged off user 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list sessions'
List all active sessions

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data.\*.id | string |  `windows session id`  |   0 
action_result.data.\*.name | string |  |   services 
action_result.data.\*.this | boolean |  |   True  False 
action_result.data.\*.type | string |  |  
action_result.data.\*.username | string |  `user name`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully listed all sessions 
action_result.summary | string |  |  
action_result.summary.num_sessions | numeric |  |   1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'deactivate partition'
Deactivate a partition

Type: **contain**  
Read only: **False**

Deactivates the system partitions of a machine, which disallows booting from said partition. The subsequent boot of the machine results in using the next option specified in the BIOS to boot from. Often used to netboot for remote reimaging.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully deactivated partition 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'activate partition'
Activate a partition

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully activated partition 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'shutdown system'
Shutdown a system

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**comment** |  optional  | Comment to show to users | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.comment | string |  |   Test shutdown 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully initiated system shutdown 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'restart system'
Restart a system

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**comment** |  optional  | Comment to show to users | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.comment | string |  |   Test restart 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully initiated system restart 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list policies'
List AppLocker Policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**location** |  required  | Which policies to list | string | 
**ldap** |  optional  | LDAP Server. Will only have an effect if 'location' is set to 'domain' | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.ldap | string |  |   LDAP://8.8.8.8/CN={31b2f340-016d-11d2-945f-00c04fb984f9},CN=Policies,CN=System,DC=domain,DC=local 
action_result.parameter.location | string |  |   local 
action_result.data.\*.Conditions.FilePublisherCondition.@BinaryName | string |  |   \* 
action_result.data.\*.Conditions.FilePublisherCondition.@ProductName | string |  |   \* 
action_result.data.\*.Conditions.FilePublisherCondition.@PublisherName | string |  |   \* 
action_result.data.\*.Conditions.FilePublisherCondition.BinaryVersionRange.@HighSection | string |  |   \* 
action_result.data.\*.Conditions.FilePublisherCondition.BinaryVersionRange.@LowSection | string |  `ip`  |   8.8.8.8 
action_result.data.\*.action | string |  |   Allow 
action_result.data.\*.description | string |  |   Allows members of the Everyone group to run packaged apps that are signed. 
action_result.data.\*.enforcement_mode | string |  |   NotConfigured 
action_result.data.\*.file_path_condition | string |  `file path`  |   %SYSTEM32%\\NOTEPAD.EXE 
action_result.data.\*.id | string |  `windows applocker policy id`  |   a9e18c21-ff8f-43cf-b9fc-db40eed693ba 
action_result.data.\*.name | string |  |   (Default Rule) All signed packaged apps 
action_result.data.\*.type | string |  |   Appx 
action_result.data.\*.user_or_group_sid | string |  `winrm user or group sid`  |   S-1-1-0 
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully listed AppLocker Policies 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'block file path'
Create a new AppLocker policy to block a file path

Type: **generic**  
Read only: **False**

By default, this policy will apply to the "Everyone" group. You can specify the user with either a variety of formats, which are documented <a href="https://technet.microsoft.com/en-us/library/ee460963.aspx" target="_blank">here</a>. By specifying LDAP, it will apply that policy to that GPO, as opposed to just the local machine. By default, Windows <b>does not</b> have the service required service running for AppLocker policies to be enforced. The <b>Application Identity</b> service must be running for AppLocker to enforce its policies.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**deny_allow** |  required  | Set this rule to allow or deny | string | 
**file_path** |  required  | File path to set rule to. Allows wildcards (i.e. C:\\Windows\\System32\\\*.exe) | string |  `file path` 
**user** |  optional  | User or group to apply rule to | string |  `winrm user or group sid` 
**rule_name_prefix** |  optional  | Prefix for new rule name | string | 
**ldap** |  optional  | LDAP Server | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.deny_allow | string |  |   allow  deny 
action_result.parameter.file_path | string |  `file path`  |   C:\\Windows\\System32\\notepad.exe 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.ldap | string |  |   LDAP://8.8.8.8/CN={31b2f340-016d-11d2-945f-00c04fb984f9},CN=Policies,CN=System,DC=domain,DC=local 
action_result.parameter.rule_name_prefix | string |  |   test 
action_result.parameter.user | string |  `winrm user or group sid`  |   Administrator 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully created AppLocker policy 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete policy'
Delete an AppLocker policy

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**applocker_policy_id** |  required  | ID of policy to delete | string |  `windows applocker policy id` 
**ldap** |  optional  | LDAP Server | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.applocker_policy_id | string |  `windows applocker policy id`  |   084ab400-83b8-432d-8dc2-f180fbe301ca 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.ldap | string |  |   LDAP://8.8.8.8/CN={31b2f340-016d-11d2-945f-00c04fb984f9},CN=Policies,CN=System,DC=domain,DC=local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully deleted AppLocker Policy 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get file'
Copy a file from the Windows Endpoint to the Vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**file_path** |  required  | Path to file | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.file_path | string |  `file path`  |   C:\\Users\\administrator.CORP\\logo.jpg  C:\\Users\\Administrator\\Desktop\\c.txt 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully retrieved file and added it to the Vault 
action_result.summary | string |  |  
action_result.summary.vault_id | string |  `sha1`  `vault id`  |   8afa5c86de9ea94ecfe5b4c0837d2543d0b20b56 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'upload file'
Copy a file from the vault to the Windows Endpoint

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**vault_id** |  required  | Vault ID of file | string |  `vault id` 
**destination** |  required  | Path to copy file to | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.destination | string |  `file path`  |   C:\\Users\\administrator.CORP\\Desktop\\aasdf.txt 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.vault_id | string |  `vault id`  |   8afa5c86de9ea94ecfe5b4c0837d2543d0b20b56 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully sent file 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'copy file'
Run the copy command on the Windows Endpoint

Type: **generic**  
Read only: **False**

For best results, both the <b>from</b> and <b>to</b> parameters should be absolute paths to their respective locations.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**from** |  required  | File source (path) | string |  `file path` 
**to** |  required  | File destination (path) | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.from | string |  `file path`  |   C:\\Windows\\System32\\notepad.exe 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.parameter.to | string |  `file path`  |   C:\\Windows\\System32\\notepad_copy.exe 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully copied files 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete file'
Run the delete command on the Windows Endpoint

Type: **generic**  
Read only: **False**

For best results, the <b>file path</b> parameter should be an absolute path to a location.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**file_path** |  required  | Path to file | string |  `file path` 
**force** |  optional  | Use the force flag for delete | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.file_path | string |  `file path`  |   C:\\Windows\\System32\\notepad.exe 
action_result.parameter.force | boolean |  |   True  False 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   8.8.8.8  8.8.8.8\\testphantom.local 
action_result.data | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |   Successfully deleted files 
action_result.summary | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 