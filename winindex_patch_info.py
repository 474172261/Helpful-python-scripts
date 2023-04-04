import sys
from bs4 import BeautifulSoup
import requests
import gzip
import urllib.request
import requests
import json
import os
import wget

file = "vmbusr.sys"
URL = "https://winbindex.m417z.com/?file="
def get_file_info(file, keyword, timerange = (0, 20250000)):
    filename = "D:\\tmp\\tmp_index\\"+file+".json.gz"

    if not os.path.exists(filename):
        req = "https://winbindex.m417z.com/data/by_filename_compressed/"+file.lower()+".json.gz"
        print("downloading {}".format(req));
        try:
            # response = urllib.request.urlopen(req)
            response = requests.get(req)
            if response.text.startswith('<!DOCTYPE html>'):
                print("no such file")
                return []
            compressed_file = response.content
            with open(filename,"wb") as f:
                f.write(compressed_file)
        except:
            print("[Error] fail to get this file")
            return []


    with gzip.open(filename, 'rb') as f:
        file_content = f.read()

    data = json.loads(file_content)

    result = {}
    for key, value in data.items():
        # print(key, type(value), value)
        if value.get('fileInfo'):
            timestamp = value.get('fileInfo')['timestamp']
            try:
                virtualSize = value.get('fileInfo')['virtualSize']
            except:
                virtualSize = 0
        else:
            timestamp = 0
            virtualSize = 0
        windows_versions = value.get('windowsVersions')
        if windows_versions:
            # print(windows_versions)
            # print('\n***\n')
            tmp = {}
            first_windows_version = list(windows_versions.keys())[0]
            min_time = 22221111
            min_key = ''
            # print(windows_versions[first_windows_version])
            # print("\n")
            flag_continue = 0
            for key in windows_versions[first_windows_version].keys():
                if not key.startswith("KB"):
                    flag_continue = 1
                    break
                # print(windows_versions[first_windows_version][key]['updateInfo'])
                t = int(windows_versions[first_windows_version][key]['updateInfo']['releaseDate'].replace('-',''), 10)
                if t < min_time:
                    # print(t)
                    min_time = t
                    min_key = key
            if flag_continue:
                continue
            key = min_key
            v = windows_versions[first_windows_version][key]
            # print("\n", key, v)
            tmp['KB'] = key
            release_date = v.get('updateInfo', {}).get('releaseDate')
            tmp['release_date'] = release_date
            tmp['release_date_int'] = int(release_date.replace('-',''))
            tmp['timestamp'] = timestamp
            tmp['virtualSize'] = virtualSize
            if virtualSize:
                tmp['file_id'] ='{:08X}{:X}'.format(timestamp, virtualSize)

            # if tmp == {}:
            #     continue
            if first_windows_version not in result:
                result[first_windows_version] = [tmp]
            else:
                result[first_windows_version].append(tmp)
    item_ret = []
    for item in result.keys():
        # print(item)
        if keyword in item:
            item_ret = result[item]
            break
    
    ret = []
    for each in item_ret:
        try:
            # print(each)
            if timerange[0] < each['release_date_int'] < timerange[1]:
                ret.append(each)
        except:
            print(each, item_ret)
            print("exit")
            exit(0)
    return ret


def get_download_link(peName, fileId):
    return 'https://msdl.microsoft.com/download/symbols/' + peName + '/' + fileId + '/' + peName;

main_lists = ["vmswitch.sys", 'vmsproxy.sys', 'storvsp.sys', 'passthruparser.sys',
'vhdparser.sys', 'vpcivsp.sys', 'vmbkmclr.sys', 'vmbusr.sys', 'vid.sys', 'hvix64.exe',
'winhvr.sys', 'vmwp.exe']
# vmusrv.dll is for vSMB of container
# vp9fs.dll sharing les host to guest, linux based containers
# hvsicontainerservice.dll defender container
part_list1 = ['pcip.sys', 'synth3dvsp.sys', 'ramparser.sys', 'vmsvcext.sys', 'lunparser.sys']

all_list = ['hvsicontainerservice.dll', 'hvsifiletrust.dll', 'hvsimgrps.dll', 'hvsiofficeiconoverlayshellextension.dll', 'hvsicontainerservice.dll', 'hvsiDspdvcclient.dll', 'hvsirdpclient.exe', 'hvsifiletrust.dll', 'hvsimgr.exe', 'HvsiMachinePolicies.dll', 'hvsimgrps.dll', 'hvsiofficeiconoverlayshellextension.dll', 'HvsiSettingsProvider.dll', 'Provider.dll', 'hvsimgr.exe', 'hvsirdpclient.exe', 'HvsiSettingsWorker.exe', 'hvsicontainerservice.dll', 'hvsigpext.dll', 'AuditSettingsProvider.dll', 'madrid.dll', 'cmclient.dll', 'vmcompute.dll', 'vmcomputeeventlog.dll', 'VmComputeProxy.dll', 'hnsproxy.dll', 'HostNetSvc.dll', 'CmService.dll', 'computestorage.dll', 'NetMgmtIF.dll', 'NvAgent.dll', 'vmsif.dll', 'vmsifcore.dll', 'vmsifproxystub.dll', 'VmSynthNic.dll', 'gns.dll', 'vmdynmem.dll', 'vmflexio.dll', 'vmiccore.dll', 'vmpmem.dll', 'vmserial.dll', 'vmsmb.dll', 'vmsynthstor.dll', 'vmuidevices.dll', 'VrdUmed.dll', 'gpupvdev.dll', 'vmchipset.dll', 'ActivationVdev.dll', 'vmwp.exe', 'sbresources.dll', 'rdp4vs.dll', 'UtilityVmSysprep.dll', 'vmbuspiper.dll', 'vmbusvdev.dll', 'VmCrashDump.dll', 'vmprox.dll', 'vmusrv.dll', 'vmvirtio.dll', 'vmwpctrl.dll', 'vmwpevents.dll', 'vfpapi.dll', 'vp9fs.dll', 'vmsmb.dll', 'icsvc.dll', 'icsvcext.dll', 'vid.dll', 'winhvplatform.dll', 'winhvemulation.dll', 'ComputeLegacy.dll', 'ComputeStorage.dll', 'ComputeCore.dll', 'ComputeNetwork.dll', 'DeviceVirtualization.dll', 'ComputeNetwork.dll', 'rdvvmtransport.dll', 'RdvgmProxy.dll', 'vmstaging.dll', 'HyperVSysprepProvider.dll', 'hgattest.dll', 'hgsclientplugin.dll', 'hgclientservice.dll', 'hgclientserviceps.dll', 'hgsclientplugin.dll', 'HgsClientWmi.dll', 'HostGuardianServiceClientResources.dll', 'NetMgmtIF.dll', 'rdp4vs.dll', 'NvAgent.dll', 'rtpm.dll', 'RdvgmProxy.dll', 'RdvGpuInfo.dll', 'RemoteFileBrowse.dll', 'TpmEngUM.dll', 'synth3dvideoproxy.dll', 'vmstaging.dll', 'vmsynth3dvideo.dll', 'vmsynthfcvdev.dll', 'vmtpm.dll', 'VmDataStore.dll', 'vmdebug.dll', 'vpcievdev.dll', 'vmemulateddevices.dll', 'VmEmulatedNic.dll', 'VmEmulatedStorage.dll', 'vmhgs.dll', 'vmicrdv.dll', 'vsconfig.dll', 'vmicvdev.dll', 'vmmsprox.dll', 'utilityVid.sys', 'hvsifltr.sys', 'vmswitch.sys', 'VmsProxy.sys', 'VmsProxyHNic.sys', 'l2bridge.sys', 'vfpext.sys', 'NdisVirtualBus.sys', 'wcifs.sys', 'hvsocketcontrol.sys', 'hvsocket.sys', 'storvsp.sys', 'passthruparser.sys', 'vhdparser.sys', 'pvhdparser.sys', 'vpcivsp.sys', 'storvsc.sys', 'vmbkmclr.sys', 'vmbkmcl.sys', 'vmbusr.sys', 'vmbus.sys', 'VMBusHID.sys', 'hyperkbd.sys', 'HyperVideo.sys', 'winhvr.sys', 'winhv.sys', 'vid.sys', 'hvservice.sys', 'hvix64.exe', 'hvcrash.sys', 'vhdmp.sys', 'vmgencounter.sys', 'vmgid.sys', 'pcip.sys', 'Synth3dVsp.sys', 'ramparser.sys', 'vmsvcext.sys', 'lunparser.sys', 'vkrnlintvsc.sys', 'vkrnlintvsp.sys', 'hnsdiag.exe', 'hvsimgr.exe', 'hvsiproxyapp.exe', 'hvsirdpclient.exe', 'hvsirpcd.exe', 'hvsievaluator.exe', 'HvsiSettingsWorker.exe', 'wdagtool.exe', 'CExecSvc.exe', 'cmdiag.exe', 'cmimageworker.exe', 'vmcompute.exe', 'VmComputeAgent.exe', 'wcsetupagent.exe', 'hcsdiag.exe', 'vfpctrl.exe', 'nmbind.exe', 'nmscrub.exe', 'nvspinfo.exe', 'vmwp.exe', 'WindowsSandbox.exe', 'hvc.exe', 'hnsdiag.exe', 'rdvgm.exe', 'vmplatformca.exe', 'vmsp.exe', 'vmconnect.exe', 'vmms.exe', 'Hvsigpext.dll', 'rdbss.sys', 'wcifs.sys', 'ntoskrnl.exe', 'vmcompute.exe', 'VmComputeAgent.exe', 'CmService.dll', 'rdsdwmdr.dll', 'rdsxvmaudio.dll']
# all_list based on https://github.com/gerhart01/Hyper-V-Internals/blob/master/Hyper-V%20components.pdf

except_list = ['computelegacy.dll', 'provider.dll', 'utilityvid.sys', 'devicevirtualization.dll', 'l2bridge.sys', 'vkrnlintvsp.sys', 'vmcomputeeventlog.dll']


start_list = list(set(all_list))

start_list = [i for i in start_list if i.lower() not in [x.lower() for x in except_list]]



if 0:
    print(get_file_info('vmswitch.sys', '1809', (20220600, 20220620)))
    exit(0)

def get_patch_info(winver, time_month):
    time_start = time_month*100
    result = []
    for each in start_list:
        ret = get_file_info(each, winver, (time_start, time_start+20))
        if ret == []:
            continue
        result.append([each, ret])
    return result

def help():
    print("""
    this.py winver date
        this.py 1809 202206
    this.py winver date name folder
        this.py 1809 202206 vmbkmclr.sys D:\\tmp\\
    winver: ['1703', '1507', '1607','1709', '1803', '2004', '1903', '1909', '1809', '11-21H2', '11-22H2', '20H2'(-22H2)]""")
    exit(0)

def main():
    winvers = ['1703', '1507', '1607','1709', '1803', '2004', '1903', '1909', '1809', '11-21H2', '11-22H2', '20H2']
    if len(sys.argv) == 3:
        winver = sys.argv[1]
        if winver not in winvers:
            help()
        
        time_month = int(sys.argv[2], 10)
        result = get_patch_info(winver, time_month)
        names = []
        for each in result:
            names.append(each[0])
            # print(each[1])
        print(names)
    elif len(sys.argv) == 4:
        winver = sys.argv[1]
        if winver not in winvers:
            help()

        winver2 = sys.argv[2]
        if winver2 not in winvers:
            help()
        
        time_month = int(sys.argv[3], 10)
        result = get_patch_info(winver, time_month)
        result2 = get_patch_info(winver2, time_month)

        names = []
        for each in result:
            names.append(each[0])
            # print(each[1])
        for each in result2:
            if each[0] in names:
                print(each[0])
        # print(names)

    elif len(sys.argv) == 5:
        winver = sys.argv[1]
        if winver not in winvers:
            help()
        
        time_month = int(sys.argv[2], 10)
        time_start = time_month*100
        target_file = sys.argv[3]
        download_folder = sys.argv[4]
        result = get_file_info(target_file, winver, (time_start-10000, time_start+15))
        print(result[-1])
        print(result[-2])
        if result[-1]['file_id'] == result[-2]['file_id']:
            print("same")
            return
        cur = result[-1]
        link = get_download_link(target_file, cur['file_id'])
        path = os.path.join(download_folder, cur['release_date']+'-'+target_file)
        if not os.path.exists(path):
            print('\nget', path)
            wget.download(link, path)

        cur = result[-2]
        link = get_download_link(target_file, cur['file_id'])
        path = os.path.join(download_folder, cur['release_date']+'-'+target_file)
        if not os.path.exists(path):
            print('\nget', path)
            wget.download(link, path)
    else:
        help()


        
if __name__ == '__main__':
    main()
