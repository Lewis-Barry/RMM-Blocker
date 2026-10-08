// Match known aliases, including helper executables which do not use the product name.
const definitions = String.raw`
TeamViewer | teamviewer|\\tv_(w32|w64|x64)\.exe$|teamtaskmanager
AnyDesk | anydesk
Ammyy Admin | ammyy|\\aa_v[^\\]*\.exe$
Parsec | parsec|\\pservice\.exe$
Atera | atera
ConnectWise Control / ScreenConnect | screenconnect|connectwisecontrol|connectwisechat|\\connectwise[^\\]*\.exe$
ConnectWise Automate / LabTech | \\lt(svc|svcmon|tray)[^\\]*\.exe$
Splashtop | splashtop|\\sr(agent|service|server|manager)[^\\]*\.exe$
NetSupport Manager | netsupport|\\(client32|pcivideo|pcicfgui|pcictlui|pcnmgr)[^\\]*\.exe$
AweSun / Aweray | awesun|aweray
Datto RMM / Autotask | centrastage|aemagent|cagservice
Dameware | dameware|\\dwrc[^\\]*\.exe$
Kaseya VSA | kaseya|\\(agentmon|kausrtsk|kaupdhlp)[^\\]*\.exe$
LogMeIn / GoToMyPC / Rescue | logmein|gotomypc|lmi_|lmiguardian|lmiignition|\\g2(host|comm|fileh?|mainh|printh|quick|tray)[^\\]*\.exe$|gopcsrv|support-logmeinrescue
GoToAssist | gotoassist|goto assist|g2ax_
GoTo Meeting / Opener | goto opener|g2m(?!ainh)|gotoscrutils
GoTo Resolve | gotoresolve|goto resolve
mRemoteNG | mremoteng
N-able / SolarWinds | n-able|basup|takecontrol|tclauncherhelper|tcintegratorcommhelper|systemmonitor|winwvc|ncstreamer
PDQ Connect / Deploy / Inventory | \\pdq|pdqconnect
Radmin | radmin|rserver3
RealVNC | realvnc|\\(winvnc4|vncserverui|vncagent|vncguihelper|vncaddrbook|vncserver|vncviewer|vncconfig)[^\\]*\.exe$
RemotePC | remotepc|rpaccess|rpcld|rpcsuite
ESQ RMM | esq sst
RustDesk | rustdesk
Supremo | supremo
Syncro | syncro
Tactical RMM | tactical
TigerVNC | tigervnc
TightVNC / Remote Ripple | tightvnc|tvnserver|tvnviewer|remoteripple|remote ripple
Chrome Remote Desktop | chrome remote desktop|remoting_
UltraViewer | ultraviewer
NinjaOne / NinjaRMM | ninja
ManageEngine | manageengine|desktopcentral|dcagent|meagenthelper|agentlessrc
Site24x7 | site24x7|\\winagent[^\\]*\.exe$
Pulseway | pulseway|pcmonitor|pcmontask
Access Remote PC | access remote pc|apc_host|rpcnet
Level | \\level
Adobe Connect | adobeconnect|adobe\\connect
AeroAdmin | aeroadmin
AliWangWang | aliwangwang|alitask
Anyplace Control | anyplace control|awhost32
AnyViewer | anyviewer
BeAnywhere Support Express | beanywhere|baseclient
BeyondTrust / Bomgar | beyondtrust|bomgar|jumpclient|jumpservice
Bitvise SSH | bitvise|bvssh
Crosstec Remote Control | crosstec
DesktopNow | desktopnow
Domotz | domotz
DWService | dwagent|dwag
OptiTune | optitune|otservice|otpowershell
eHorus / Pandora RC | ehorus
EMCO Remote Installer | \\emco\\
Ericom | ericom|\\accessserver[^\\]*\.exe$
ezHelp | ezhelp
FastViewer | fastviewer|fastmaster|fastclient
SimpleHelp | simplehelp|simplegateway|simpleservice|jwrapper-remote access|\\remote access[^\\]*\.exe$
GetScreen | getscreen
GoToHTTP | gotohttp
Goverlan / EV Reach | goverlan|goverrmc|govagent|govreach|govsrv|pj technologies
HelpU | helpu
Impero | impero
Instant Housecall | instant housecall|instanthousecall|ihcserver
ITarian / Comodo | itarian|comodo|itsm|rmmservice|\\rmm\.(agent|webremote|rtc\.proxy)|\\agentu[^\\]*\.exe$
JumpCloud | jumpcloud
Jump Desktop | jumpdesktop|jumpconnect|jumpupdater|phase five systems
Kabuto | kabuto
KHelpDesk | khelpdesk
Laplink | laplink|llrcservice
MeshCentral | meshcentral|meshagent
MioNet | mionet
MobaXterm | mobaxterm
Naverisk | naverisk
Netop Remote Control | netop|netop ondemand|danware|\\(nhstw32|nldrw32|nhostsvc|ngstw32|wfreerdp)[^\\]*\.exe$
Netviewer | netviewer|\\nv(client|console)[^\\]*\.exe$
Panorama9 | panorama9|p9agent
Parallels Access | parallels|prl_
pcAnywhere | pcanywhere|pcaquickconnect|awrem32|winaw32
PocketCloud | pocketcloud|wyse
S3 Browser | s3browser|s3 browser
DragonDisk | dragondisk
Bluetrait | bluetrait
ISL Online | isl online|isllight|islalwayson
Ivanti / LANDesk | landesk|ivanti|ldinv32|ldsensors|issuser|rcengmgru
NetSarang Xshell / Xftp | netsarang|xshell|xftp
OnionShare | onionshare
SmartFTP | smartftp
Xpra | xpra
SysAid | sysaid
Remote Utilities | remote utilities|rutserv|rutview|rfusclient
FleetDeck | fleetdeck
remote.it | remoteit|remote\.it|remote-it
Tencent QQ | \\qq[^\\]*\.exe$
Senso | \\senso
Remobo | remobo
MSP360 / CloudBerry Backup | cloud\.backup|\\(cbb|cbbackupplan)\.exe$|online backup
FixMe.IT | fixmeit|\\ti(client|expert)[^\\]*\.exe$
LiteManager | litemanager|romserver|romviewer|romfusclient|lmnoipserver
Mikogo / BeamYourScreen | mikogo|beamyourscreen
Rapid7 Insight | rapid7|ir_agent
Cloud RAS | cloudra
Royal TS / Royal Server | royalts|royalserver
GP remote executables (generic names) | \\gp[345]\.exe$
IntelliAdmin | intelliadmin|iadmin|\\iit\.exe$
Microsoft Remote Desktop / RDP | termsrv|mstsc|\\(rdp|rd|remote desktop|remotedesktop)\.exe$
RDP Wrapper | rdpconf|rdpcheck|rdpwinst
Tanium | tanium|\\tpowershell
Rsupport RemoteView / RemoteCall | remoteview|remotesupportplayer|rpcvieweruiu|rpwhostscr|rvagent|rvagtray|rcstartsupport|rxstartsupport|rcclinet|\\rv\.exe$
PsExec | psexec
DeskRoll | deskroll
pcvisit | pcvisit
Acronis Cyber Protect Connect | acroniscyberprotectconnect
Action1 | action1
AlloCentra | allocentra
Aspia | aspia
Alpha RMM | alphaagent
Beaconly | beacon-agent
BeInSync | beinsync
Breeze | breeze
Pixo IT | pixoit
Weezo | weezo|weclipboard|wecliboard|weprtct|wemonc|weinstsvc
ControlR | controlr
Freshservice | freshservice|freshworks|freshdesk|\\fs(agent|wmi|probe)[^\\]*\.exe$
Gorelo | gorelo
GxM RMM | gxm
HeartbeatRM | heartbeatrm|hbrm
HelpBeam | helpbeam
HelpWire | helpwire
HopToDesk | hoptodesk
I'm InTouch | i'm intouch|intouch
ImmyBot | immy
InvGate | invgate|inventec
ITAgent RMM | itagentrmm
Komari | komari
Lavawall | lavawall
LightRMM | lightrmm
LS RMM | ls rmm
Lunixar | lunixar
MiniRMM | minirmm
Monitic | moniti
mRemote Agent | mremote-agent
MSP Agent | \\msp-agent|\\msp agent
NetLock RMM | netlock
NetMaster | netmaster
Backdrop Connect | connect\.backdrop
Nexus RMM | nexusrmm
Nezha | nezha
NoMachine | nomachine|nxservice|nxplayer|\\nxd\.exe$
Obliance | obliance
Opale | opale
OpenUEM | openuem
OpenDesk RMM | opendesk
OpsBridge | opsbridge
PcHelpWare | pchelpware
Pilixo | pilixo
ProxiPort | proxiport
CSExec | csexec
RDP2TCP | rdp2tcp|tdp2tcp
Remcos | remcos
RemMon | remmon
RemoteAgent | remoteagentagent
Remotely | remotely_
RemSupp | remsupp
RG Supervision | rg_supervision|rg-supervision
RMMmax | rmmmax
Rodex | rodex
RuDesktop / RMS | rudesktop|remote manipulator|\\(rhost|rviewer)[^\\]*\.exe$
Sentinel RMM Agent | sentinel-agent
Server-Eye | servereye
SetMe | setme|tinunattended|tinclient
Sorillus | sorillus
SuperOps | superops|ssuagent
Iperius Remote | iperius
rdesktop | \\rdesktop[^\\]*\.exe$
Apache Guacamole | guacd
XCmd | xcmd
KiTTY | kitty
Auvik | auvik
myGreenPC | mygreenpc
Seetrol | seetrol
TSIRC executable (unconfirmed tool) | tsircusr
NateOn | nateon
ScreenMeet | screenmeet
Sunlogin / Oray | orayremote|sunlogin
PuTTY Tray | puttytray
Tailscale | tailscale
ESET Remote Administrator | \\eraagent|\\eratool|\\era\.exe$
Quick Assist | \\quickassist
OCS Inventory | ocsinventory|ocsservice
TurboMeeting | turbomeeting
RemCom | remcom
Pocket Controller | pocketcontroller
Distant Desktop | distant-desktop|ddsystem|\\dd\.exe$
Zoho Assist / Meeting | zoho|za_access|za_connect|zaservice|zmagent
ToDesk | \\todesk
ngrok | ngrok
Zero RMM | zero-powershell
Cloudflare Tunnel | cloudflared
XEOX | xeox
NTRsupport | ntrsupport|ntrntservice
O&O Syspectr | oosys|oolocker|syspectr
SecureCRT | securecrt
RemotePass | remotepass
Webex PCNow | webexpcnow
Rocket Remote Desktop | rocketremotedesktop
TiFlux | tiflux|\\ti(agent|service|updateservice)[^\\]*\.exe$
Total Network Inventory | tniwinagent
Total Software Deployment | total software deployment|tsdservice
TrustConnect | trustconnect
DocConnect | docconnect
UltraVNC | ultravnc|uvnc|winvncstub|winvncsc|\\winvnc\.exe$
UniRMM | unirmm
Vicarius Topia | vicarius|topiad
Vector / LANutil | vector|lanutil|\\(clboot32|cldist32|cldistsvc|clmeter32|clmetersvc|winchk32|lutinfow32|lusmbios32|lulogon|luguard|luedit|vnlselfupdate|vnldriverinstaller|vecwait|vnconfigutils|mqmailintegration)[^\\]*\.exe$
Zecurit | zecurit
ToolsIQ | toolsiq
Borealis | borealis|bsag
Roster | roster
Miradore | miradore
CrossLoop | crossloop
Alpemix | alpemix
ShowMyPC | showmypc|smpcsetup
RPort | \\rport
PAExec | paexec
Absolute / Computrace | ctes
Remote Workforce | remote workforce
Neturo | neturo
Screen capture rule | screancap
Connect / Support tools (generic names) | \\(connect|connectappsetup|connectshellsetup|connectdetector|supporttool|manuallauncher)\.exe$
`.trim().split("\n").map(line => {
  const [name, pattern] = line.split(" | ");
  return { name, pattern: new RegExp(pattern, "i") };
});

// These vendor-level folders overlap multiple products. Expose that overlap explicitly.
const sharedFolders = new Map([
  ["\\connectwise\\", ["ConnectWise Control / ScreenConnect", "ConnectWise Automate / LabTech"]],
  ["\\solarwinds\\", ["N-able / SolarWinds", "Dameware"]],
]);

export function classifyRule(rule) {
  const path = (rule.getAttribute("FilePath") || rule.getAttribute("FileName") || "").replaceAll("*", "");
  const shared = sharedFolders.get(path.toLowerCase());
  if (shared) return { names: shared, unclassified: false };
  const matches = definitions.filter(definition => definition.pattern.test(path));
  if (matches.length > 1) {
    throw new Error(`Ambiguous tool mapping for ${path}: ${matches.map(match => match.name).join(", ")}`);
  }
  if (matches.length) return { names: [matches[0].name], unclassified: false };
  const label = path.split("\\").filter(Boolean).join(" / ") || rule.getAttribute("ID");
  return { names: [`Unclassified: ${label}`], unclassified: true };
}
