import paramiko

def scan_ssh(target):
    vulnerabilities = []
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target, port=22, username='root', password='password')
        ssh.exec_command('uname -a')
        ssh.close()
    except paramiko.ssh_exception.AuthenticationException:
        vulnerabilities.append({'type': 'SSH vulnerability', 'details': 'Authentication error.'})
    except paramiko.ssh_exception.SSHException as e:
        vulnerabilities.append({'type': 'SSH vulnerability', 'details': str(e)})
    except Exception as e:
        vulnerabilities.append({'type': 'SSH vulnerability', 'details': str(e)})
    return vulnerabilities