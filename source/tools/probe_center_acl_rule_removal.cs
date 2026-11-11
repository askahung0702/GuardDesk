// Non-center, self-owned NTFS fixture. Reproduces the delivered ACL operation.
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
class ProbeCenterAclRuleRemoval {
 static void Dump(string phase,DirectorySecurity s) {
  Console.WriteLine(phase+" "+s.GetSecurityDescriptorSddlForm(AccessControlSections.Access));
  foreach(FileSystemAccessRule r in s.GetAccessRules(true,true,typeof(SecurityIdentifier)))
   Console.WriteLine(r.IdentityReference+" mask="+((uint)r.FileSystemRights).ToString("x")+" inherited="+r.IsInherited+" flags="+r.InheritanceFlags+"/"+r.PropagationFlags);
 }
 static int Main(string[] args) {
  try { return Run(args); } catch(Exception e) { Console.WriteLine(e.GetType().Name+": "+e.Message); return 1; }
 }
 static int Run(string[] args) {
  string root=Path.GetFullPath(args[0]);
  if(!root.Contains("center-source-permissions-094-004") || Directory.Exists(root))throw new Exception("Fresh owned fixture required");
  Directory.CreateDirectory(root);string child=Path.Combine(root,"child");
  var sid=WindowsIdentity.GetCurrent().User.Value;
  var initial=new DirectorySecurity();
  initial.SetSecurityDescriptorSddlForm("O:"+sid+"D:P(A;OICI;FA;;;"+sid+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;4;;;BU)(A;CI;2;;;BU)",AccessControlSections.Access|AccessControlSections.Owner);
  Directory.SetAccessControl(root,initial);Directory.CreateDirectory(child);
  var s=Directory.GetAccessControl(child);Dump("BEFORE",s);
  s.SetAccessRuleProtection(true,true);Dump("PROTECTED_MEMORY",s);
  foreach(FileSystemAccessRule r in s.GetAccessRules(true,true,typeof(SecurityIdentifier)))
   if(r.AccessControlType==AccessControlType.Allow && r.IdentityReference.Value=="S-1-5-32-545" && (((uint)r.FileSystemRights)&0x500D0156)!=0)s.RemoveAccessRuleSpecific(r);
  s.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"),FileSystemRights.ReadAndExecute,InheritanceFlags.ObjectInherit|InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
  Dump("AFTER_MEMORY",s);Directory.SetAccessControl(child,s);Dump("READBACK",Directory.GetAccessControl(child));
  return 0;
 }
}
