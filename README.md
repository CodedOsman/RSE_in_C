# RSE_in_C
A remote code exceution project in C language

<h1>This project was built for educational purposes.</h1>
<h3> Features: </h3>
<hr>
<h4>Server:</h4><p>The script to run on your attacking machine.<br>This script listens for connections and allows you to execute commands remotely on the target machine.</p>
<h4>Client:</h4><p>The script that runs on the target machine. This starts as a process on the target machine without displaying active windows. It is responsible for communicating responses to the server (remotely)</p>
<h4>Keylogger:</h4><p>This script logs keystrokes and saves on the target machine.</p>

<h5>Compile "backdoor.c" wih the command:</h5><p>i686 -w64 -mingw32 -gcc -o [your_preferred_name.exe] backdoor.c -lwsock32 -lwininet</p>

<h4>Usage:</h4> 
<p> q: Exits the program</p>
<p> keylog_start: Starts keylogger </p>
<p> cd: Change directory</p>
<p> The remaining commands are the default windows shell commands</p>
<h1>NB: Use this project with caution. You are responsible for your actions!</h1>
