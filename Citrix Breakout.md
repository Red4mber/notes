# Tips to break out of Citrix restricted environments

Citrix is a popular software used by companies wanting to harden the security of their employees desktop environment. 
Most organisations will implement such "lock-down" measures in an effort to prevent or minimize the impact of threat actors.
In most of these environments, a search for `cmd.exe` or `powershell.exe` will yield no results, similarly, access to `C:\Windows\System32` will trigger an error, preventing access to critical files on the system. 

## Bypassing path restrictions

If we open Explorer and try to access a directory like `C:\Users`, we will receive an error saying 'Access to the resource has been disallowed'.

We can bypass this restriction by using a dialog, like the one windows create when you search for a file to open on programs such as `paint` or `notepad`, then input a [UNC Path](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths) such as `\\127.0.0.1\C$\Users` inside.

Most of the bypasses will use such dialog boxes, as they are not as .

Be using this same technique we should also be able to access a remote SMB server : `\\<Server IP>\<Share>\<file path>`
Like this we can easily access our own share from where we can execute our own scripts and executables

An easy way to navigate the system despite the restrictions is to use alternatives to explorer.exe, like Q-Dir or Explorer++ 
Similarly, there are alternatives to regedit, like Simpleregedit, Uberregedit and SmallRegistryEditor

Another technique to get a command shell is to modify an existing shortcut (or generate one using powershell)

