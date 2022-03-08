[comment]: # "Auto-generated SOAR connector documentation"
# Windows Remote Management

Publisher: Splunk  
Connector Version: 2\.2\.4  
Product Vendor: Microsoft  
Product Name: Windows Remote Management  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app integrates with the Windows Remote Management service to execute various actions

[comment]: # ""
[comment]: # "    File: README.md"
[comment]: # "    Copyright (c) 2018-2022 Splunk Inc."
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Windows Remote Management asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**endpoint** |  optional  | string | IP/Hostname \(For TEST CONNECTIVITY and default, if not provided in an action\)
**verify\_server\_cert** |  optional  | boolean | Verify Server Certificate
**default\_protocol** |  optional  | string | Default protocol for actions
**default\_port** |  optional  | numeric | Default port for actions
**domain** |  optional  | string | Domain
**username** |  required  | string | Username
**password** |  required  | password | Password
**transport** |  required  | string | Type of transport to use

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

Unless you implement a custom parser, this action will always succeed regardless of the input\. Either a <b>command</b> or pair of <b>command\_id</b> and <b>shell\_id</b> must be specified\. If a <b>command\_id</b> is present, all other parameters will be ignored\. <p><b>Note\:</b> The command\_id and shell\_id you provide to fetch the output can only be used once because once the output is fetched successfully server will remove output from its cache\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**command** |  optional  | The command to be run | string | 
**arguments** |  optional  | The arguments for the command | string | 
**parser** |  optional  | The vault ID of a custom parser to use for output | string |  `vault id` 
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**async** |  optional  | Start the command, but don't wait for output | boolean | 
**command\_id** |  optional  | Command ID of async command \(Provide with shell\_id\) | string |  `winrm command id` 
**shell\_id** |  optional  | Shell ID of async command \(Provide with command\_id\) | string |  `winrm shell id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.arguments | string | 
action\_result\.parameter\.async | boolean | 
action\_result\.parameter\.command | string | 
action\_result\.parameter\.command\_id | string |  `winrm command id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.parser | string |  `vault id` 
action\_result\.parameter\.shell\_id | string |  `winrm shell id` 
action\_result\.data\.\*\.status\_code | numeric | 
action\_result\.data\.\*\.std\_err | string | 
action\_result\.data\.\*\.std\_out | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.command\_id | string |  `winrm command id` 
action\_result\.summary\.shell\_id | string |  `winrm shell id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run script'
Run a PowerShell script on the endpoint

Type: **generic**  
Read only: **False**

The script you provide can either be in the vault, or it can just be a string of the script to run\. If both values are present, it will use the <b>script\_file</b> over the <b>script\_str</b>\. Unless you implement a custom parser, this action will always succeed regardless of the input\. If <b>command\_id</b> and <b>shell\_id</b> are present, <b>script\_file</b> and <b>script\_str</b> will be ignored\. This action will fail if at least one of <b>script\_file</b>, <b>script\_str</b>, or the pair of <b>command\_id</b> and <b>shell\_id</b> are not specified\. <p><b>Note\:</b> The command\_id and shell\_id you provide to fetch the output can only be used once because once the output is fetched successfully server will remove output from its cache\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**script\_file** |  optional  | The vault ID of a PowerShell script to run | string |  `vault id` 
**script\_str** |  optional  | A PowerShell script to run | string | 
**parser** |  optional  | The vault ID of a custom parser to use for output | string |  `vault id` 
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**async** |  optional  | Start the command, but don't wait for output | boolean | 
**command\_id** |  optional  | Command ID of async command \(Provide with shell\_id\) | string |  `winrm command id` 
**shell\_id** |  optional  | Shell ID of async command \(Provide with command\_id\) | string |  `winrm shell id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.async | boolean | 
action\_result\.parameter\.command\_id | string |  `winrm command id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.parser | string |  `vault id` 
action\_result\.parameter\.script\_file | string |  `vault id` 
action\_result\.parameter\.script\_str | string | 
action\_result\.parameter\.shell\_id | string |  `winrm shell id` 
action\_result\.data\.\*\.status\_code | numeric | 
action\_result\.data\.\*\.std\_err | string | 
action\_result\.data\.\*\.std\_out | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.command\_id | string |  `winrm command id` 
action\_result\.summary\.shell\_id | string |  `winrm shell id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list processes'
List the currently running processes

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.handles | numeric | 
action\_result\.data\.\*\.name | string |  `process name` 
action\_result\.data\.\*\.non\_paged\_memory | numeric | 
action\_result\.data\.\*\.paged\_memory | numeric | 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.processor\_time\_\(s\) | numeric | 
action\_result\.data\.\*\.virtual\_memory | numeric | 
action\_result\.data\.\*\.working\_set | numeric | 
action\_result\.data\.\*\.session\_id | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.num\_processes | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'terminate process'
Terminate a process

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**pid** |  optional  | The PID of the process to terminate | numeric |  `pid` 
**name** |  optional  | Name of program to terminate, accepts wildcards | string |  `process name` 
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.name | string |  `process name` 
action\_result\.parameter\.pid | numeric |  `pid` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list connections'
List all active connections

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.foreign\_address\_ip | string |  `ip` 
action\_result\.data\.\*\.foreign\_address\_port | string |  `port` 
action\_result\.data\.\*\.local\_address\_ip | string |  `ip` 
action\_result\.data\.\*\.local\_address\_port | string |  `port` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.protocol | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.num\_connections | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list firewall rules'
List the firewall rules

Type: **investigate**  
Read only: **True**

When you are using the <b>other</b> parameter, you can match for any field which is returned in the action result\. It will only return a rule if it matches all of the criteria, not if it matches at least one\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter\_port** |  optional  | Only show firewall rules acting on this port | string |  `port` 
**filter\_ip** |  optional  | Only show firewall rules acting on this ip | string |  `ip` 
**direction** |  optional  | Only show firewall rules in this direction | string | 
**protocol** |  optional  | Only show firewall rules using this protocol | string |  `winrm protocol` 
**other** |  optional  | JSON object of key value pairs of other fields to match | string | 
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.direction | string | 
action\_result\.parameter\.filter\_ip | string |  `ip` 
action\_result\.parameter\.filter\_port | string |  `port` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.other | string | 
action\_result\.parameter\.protocol | string |  `winrm protocol` 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.direction | string | 
action\_result\.data\.\*\.edge\_traversal | string | 
action\_result\.data\.\*\.enabled | string | 
action\_result\.data\.\*\.grouping | string | 
action\_result\.data\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.local\_port | string |  `port` 
action\_result\.data\.\*\.profiles | string | 
action\_result\.data\.\*\.protocol | string |  `winrm protocol` 
action\_result\.data\.\*\.remote\_ip | string |  `ip` 
action\_result\.data\.\*\.remote\_port | string |  `port` 
action\_result\.data\.\*\.rule\_name | string |  `windows firewall rule name` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.num\_rules | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete firewall rule'
Remove a firewall rule using netsh

Type: **generic**  
Read only: **False**

This action will invoke the command <code>netsh advfirewall firewall delete rule</code>, and the rest is determined by the input\. At a minimum, the rule name must be provided, but if you need to you can also specify any other arguments which the command accepts, in the same manner, that input from the <b>add firewall rule</b> gets added\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | The name of the rule to remove | string |  `windows firewall rule name` 
**dir** |  optional  | Blocks inbound or outbound traffic | string | 
**remote\_ip** |  optional  | Firewall rule acts on this remote IP | string |  `ip` 
**local\_ip** |  optional  | Firewall rule acts on this local IP | string |  `ip` 
**remote\_port** |  optional  | Firewall rule acts on this remote port | string |  `port` 
**local\_port** |  optional  | Firewall rule acts on this local port | string |  `port` 
**protocol** |  optional  | Firewall rule acts on this protocol | string |  `winrm protocol` 
**other** |  optional  | JSON object of key value pairs for other parameters to include | string | 
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.dir | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.local\_ip | string |  `ip` 
action\_result\.parameter\.local\_port | string |  `port` 
action\_result\.parameter\.name | string |  `windows firewall rule name` 
action\_result\.parameter\.other | string | 
action\_result\.parameter\.protocol | string |  `winrm protocol` 
action\_result\.parameter\.remote\_ip | string |  `ip` 
action\_result\.parameter\.remote\_port | string |  `port` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.rules\_deleted | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block ip'
Create a firewall rule to block a specified IP

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**name** |  required  | The name of the rule to add | string |  `windows firewall rule name` 
**remote\_ip** |  required  | Block this IP | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.name | string |  `windows firewall rule name` 
action\_result\.parameter\.remote\_ip | string |  `ip` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add firewall rule'
Add a firewall rule using netsh

Type: **generic**  
Read only: **False**

This action will invoke the command <code>netsh advfirewall firewall add rule</code>, where the rest is determined by the input\. Each <b>key\-value</b> pair from the <b>other</b> parameter will be added in the form of <b>key</b>=<b>value</b>\. The user input will  be sanitized\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | The name of the rule to add | string |  `windows firewall rule name` 
**dir** |  required  | Block inbound or outbound traffic | string | 
**action** |  required  | What the firewall will do with packets | string | 
**remote\_ip** |  optional  | Firewall rule acts on this remote IP | string |  `ip` 
**local\_ip** |  optional  | Firewall rule acts on this local IP | string |  `ip` 
**remote\_port** |  optional  | Firewall rule acts on this remote port | string |  `port` 
**local\_port** |  optional  | Firewall rule acts on this local port | string |  `port` 
**protocol** |  optional  | Firewall rule acts on this protocol | string |  `winrm protocol` 
**other** |  optional  | JSON object of key value pairs for other parameters to include | string | 
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.action | string | 
action\_result\.parameter\.dir | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.local\_ip | string |  `ip` 
action\_result\.parameter\.local\_port | string |  `port` 
action\_result\.parameter\.name | string |  `windows firewall rule name` 
action\_result\.parameter\.other | string | 
action\_result\.parameter\.protocol | string |  `winrm protocol` 
action\_result\.parameter\.remote\_ip | string |  `ip` 
action\_result\.parameter\.remote\_port | string |  `port` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'logoff user'
Logoff a user

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**session\_id** |  required  | Session ID | string |  `windows session id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.session\_id | string |  `windows session id` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list sessions'
List all active sessions

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data\.\*\.id | string |  `windows session id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.this | boolean | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.num\_sessions | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'deactivate partition'
Deactivate a partition

Type: **contain**  
Read only: **False**

Deactivates the system partitions of a machine, which disallows booting from said partition\. The subsequent boot of the machine results in using the next option specified in the BIOS to boot from\. Often used to netboot for remote reimaging\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'activate partition'
Activate a partition

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'shutdown system'
Shutdown a system

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**comment** |  optional  | Comment to show to users | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'restart system'
Restart a system

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**comment** |  optional  | Comment to show to users | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policies'
List AppLocker Policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**location** |  required  | Which policies to list | string | 
**ldap** |  optional  | LDAP Server\. Will only have an effect if 'location' is set to 'domain' | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.ldap | string | 
action\_result\.parameter\.location | string | 
action\_result\.data\.\*\.Conditions\.FilePublisherCondition\.\@BinaryName | string | 
action\_result\.data\.\*\.Conditions\.FilePublisherCondition\.\@ProductName | string | 
action\_result\.data\.\*\.Conditions\.FilePublisherCondition\.\@PublisherName | string | 
action\_result\.data\.\*\.Conditions\.FilePublisherCondition\.BinaryVersionRange\.\@HighSection | string | 
action\_result\.data\.\*\.Conditions\.FilePublisherCondition\.BinaryVersionRange\.\@LowSection | string |  `ip` 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.enforcement\_mode | string | 
action\_result\.data\.\*\.file\_path\_condition | string |  `file path` 
action\_result\.data\.\*\.id | string |  `windows applocker policy id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.user\_or\_group\_sid | string |  `winrm user or group sid` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block file path'
Create a new AppLocker policy to block a file path

Type: **generic**  
Read only: **False**

By default, this policy will apply to the "Everyone" group\. You can specify the user with either a variety of formats, which are documented <a href="https\://technet\.microsoft\.com/en\-us/library/ee460963\.aspx" target="\_blank">here</a>\. By specifying LDAP, it will apply that policy to that GPO, as opposed to just the local machine\. By default, Windows <b>does not</b> have the service required service running for AppLocker policies to be enforced\. The <b>Application Identity</b> service must be running for AppLocker to enforce its policies\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**deny\_allow** |  required  | Set this rule to allow or deny | string | 
**file\_path** |  required  | File path to set rule to\. Allows wildcards \(i\.e\. C\:\\Windows\\System32\\\*\.exe\) | string |  `file path` 
**user** |  optional  | User or group to apply rule to | string |  `winrm user or group sid` 
**rule\_name\_prefix** |  optional  | Prefix for new rule name | string | 
**ldap** |  optional  | LDAP Server | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.deny\_allow | string | 
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.ldap | string | 
action\_result\.parameter\.rule\_name\_prefix | string | 
action\_result\.parameter\.user | string |  `winrm user or group sid` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete policy'
Delete an AppLocker policy

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**applocker\_policy\_id** |  required  | ID of policy to delete | string |  `windows applocker policy id` 
**ldap** |  optional  | LDAP Server | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.applocker\_policy\_id | string |  `windows applocker policy id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.ldap | string | 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Copy a file from the Windows Endpoint to the Vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**file\_path** |  required  | Path to file | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.vault\_id | string |  `sha1`  `vault id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'upload file'
Copy a file from the vault to the Windows Endpoint

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**vault\_id** |  required  | Vault ID of file | string |  `vault id` 
**destination** |  required  | Path to copy file to | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.destination | string |  `file path` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'copy file'
Run the copy command on the Windows Endpoint

Type: **generic**  
Read only: **False**

For best results, both the <b>from</b> and <b>to</b> parameters should be absolute paths to their respective locations\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**from** |  required  | File source \(path\) | string |  `file path` 
**to** |  required  | File destination \(path\) | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.from | string |  `file path` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.to | string |  `file path` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete file'
Run the delete command on the Windows Endpoint

Type: **generic**  
Read only: **False**

For best results, the <b>file path</b> parameter should be an absolute path to a location\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | IP/Hostname | string |  `ip`  `host name` 
**file\_path** |  required  | Path to file | string |  `file path` 
**force** |  optional  | Use the force flag for delete | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.force | boolean | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 