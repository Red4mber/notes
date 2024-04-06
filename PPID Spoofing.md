## Summary
PPID stands for Parent Process ID. It refers to the process identifier of the parent process that spawned a child process. PPID spoofing is a technique used by malware or rootkits to hide their presence by manipulating the reported PPID value. This makes the malicious process appear as if it was started by a trusted process rather than the actual malware dropper.
### Short Summary
I started by writing the `get_all_processes` and `get_pid_by_process_name` so i don't have to hardcode the PID, but you don't really have to.
The PID is used to open a handle to the target process using the `OpenProcess` function. 

Then, we will be first initializing, then configuring the process attribute list, using the `InitializeProcThreadAttributeList` function.
We will then use the `UpdateProcThreadAttribute` function to update the attribute list using the correct attributes and passing it the handle to the target parent process, and not forgetting to update the attribute containing the size of the structure.

We can now create the process, using `CreateProcessA` passing it the necessary information such as the name of the executable (as a LPSTR) and the two structures we created : startup_info and process_info

## Detection
Best doc about event tracing here : [A beginner's all inclusive guide to ETW](https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw)
### Creating a tracing session
For this, we will need to capture all events related to processes, using the `logman create` command to create a trace.
We will use the `-p` argument to specify the provider `Microsoft-Windows-Kernel-Process` with the event code 0x10 (which is WINEVENT_KEYWORD_PROCESS) and The argument flag `-ets` to create an event tracing session
Once created, we can start it, then use `logman query` to check if it's running successfully (with `-ets` to query the tracing session directly).
```powershell
logman create trace ppid-spoofing -p Microsoft-Windows-Kernel-Process 0x10 -ets
logman start ppid-spoofing
logman query ppid-spoofing -ets
```
### Finding the real PPID in the log
You can now run your PPID spoofed executable, and when it's done we'll try to find it in the logs. 
In the output of the previous `logman query` command, you should see the `Output location` field, with a path to a `.etl` file, this is the event tracing log.  

Launch the Event Viewer and click on "Saved Logs" to open the log file. You should see the events captured by your session so far. Find the event corresponding to your PPID-spoofed process creation and open it, then check the XML view in the Details tab.  

In the EventData section, you should see most relevant information like the PID or the path of the executable, but also the field ParentProcessID containing the spoofed PPID.

However you might notice that above the EventData section, we have the `Execution` field containing the actual parent PID !!
### Automating the detection <Work in progress>
So we have now know the event log does stores the actual PPID as well as the spoofed PPID, to automate detection we can simply write a consumer to capture process events.
Then parse the event and check if `ParentPID != Execution ProcessID`.
If the values do not match, then we probably detected an attempt at PPID spoofing and we can now launch an alert and/or kill the process.








