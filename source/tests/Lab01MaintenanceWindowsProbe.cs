using System;
using System.Collections.Generic;
using System.IO;
using GuardDeskMaintenance;
class Probe {
    public static int Main(string[] args){
        var report=new Dictionary<string,object>{{"settings_changed",false},{"agent_executed",false}};
        try{report["defender_status"]=WindowsApi.Defender();}catch(Exception e){report["defender_query_error"]=new{type=e.GetType().Name,hresult=e.HResult.ToString("X8")};}
        try{report["events"]=WindowsApi.DefenderEvents(DateTime.UtcNow.AddMinutes(-1));}catch(Exception e){report["event_query_error"]=new{type=e.GetType().Name,hresult=e.HResult.ToString("X8")};}
        try{WindowsApi.ScheduledWorker("ee8da3bbc21decab423cd881",@"C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe");report["existing_AIO_task_query"]="matched_running_system";}catch(Exception e){report["task_query_error"]=new{type=e.GetType().Name,hresult=e.HResult.ToString("X8"),code=e is Review?e.Message:"WINDOWS_API_ERROR"};}
        File.WriteAllText(args[0],Checks.Serializer(65536).Serialize(report));Console.WriteLine(Checks.Serializer(65536).Serialize(report));return 0;
    }
}
