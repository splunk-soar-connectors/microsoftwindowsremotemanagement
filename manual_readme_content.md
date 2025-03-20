Without additional configuration on the proxy server, it will not be possible to connect to WinRM
using NTLM authentication through an HTTP(S) proxy. If authentication is set to basic, then it will
still work, however.

To use the proxy settings you need to add the proxy server as an environment variable. You can add
an environment variable using the below command.

- For Linux/Mac: `      export HTTP_PROXY="http://<proxy server>:<proxy port>/"     `
- For Windows powershell: `      $env:HTTP_PROXY="http://<proxy server>:<proxy port>/"     `

If the user tries to add any invalid proxy URL, the proxy will be bypassed and won't affect the
app's connectivity.

To use this app you must have the Windows Remote Management service running on the endpoint you wish
to connect to. For help regarding this process, consult this link:
<https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx>

WinRM Ports Requirements (Based on Standard Guidelines of [IANA
ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

- WinRM(service) TCP(transport layer protocol) port for Windows Remote Management Service - 47001

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

```shell
        
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

```shell
        
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

To authenticate using SSL certificates, select `certificate` as the authentication method in the asset configuration and provide the following configuration parameters:

- **Path to SSL certificate PEM file** (cert_pem_path) - The path to the signed certificate file that is trusted by the Windows instance, in PEM format.

- **Path to SSL key file** (cert_key_pem_path) - The path to the key file used to generate the `cert_pem` file.

- **Path to trusted CRT file** (ca_trust_path) - The certificate of the certificate authority that signed the certificate file. This is needed only if you are using your own certificate authority.

It is recommended to place these files under the `<PHANTOM_HOME>/etc/ssl/` directory. Ensure that these files are readable by the `phantom-worker` user.

#### Steps to Enable [Certificate Authentication](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https) in WinRM:

- Check if Certificate Authentication is enabled:

  ```
  winrm get winrm/config/service/auth
  ```

- Enable Certificate Authentication if it is not already enabled:

  ```
  winrm set winrm/config/service/auth '@{Certificate="true"}'
  ```

- [Import the Certificate](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2025-ps) into Trusted [Certificate Stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores).

- Link the [client certificate](https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_wsman_provider?view=powershell-7.4#creating-a-new-client-certificate) to the user account for enabling secure authentication using the certificate by running this command:

  ```
  New-Item -Path WSMan:\localhost\ClientCertificate -URI * -Issuer <Thumbprint> -Credential (Get-Credential) -Force
  ```

### Kerberos Authentication

To authenticate using Kerberos, select `kerberos` authentication in asset configuration and provide hostname and username used for authorization.
You'll also need to setup your instance to support Kerberos:

- Kerberos packages have to be installed:

  - for Debian/Ubuntu/etc: `sudo apt-get install krb5-user`
  - for RHEL/CentOS/etc: `sudo yum install krb5-workstation krb5-libs`

- `/etc/krb5.conf` needs to be properly configured for your realm and kdc

- If there is no DNS configuration, `hosts` file will need to have mappings for server with mssccm under same domain as on Windows server

- `kinit` must be run for principal that will be used to connect to msccm

- It should be noted that Kerberos tickets will expire, so it is recommended to use a script to
  run `kinit` periodically to refresh the ticket for the user, alternatively `keytab` file can be created on server and used on client for connectivity.
