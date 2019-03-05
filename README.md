Real Time Streaming Protocol(RTSP) Fuzzer Tools 
===


# Description
針對的自動化模糊測試工具

適用於Linux、Windows、MacOS
建議使用Python 2.7.x環境執行
下載後，目錄內會以下四個檔案

* README.TXT 說明檔
* LOG.TXT 測試過程的日誌檔
* rtsp.conf 參數設定檔
* rtspfuzz.py 檢測程式


測試目的為造成Server端在解析封包過程中發生錯誤，造成設備重新開機或其他異常行為，驗證IOT設備是否存在被Client端所發出的Request造成服務中斷的弱點。

# Features
針對RTSP協定中定義的請求方法對各欄位增加額外隨機產生的字元進行測試，例如'OPTIONS'、'DESCRIBE'、'SETUP'、'TEARDOWN'、'PAUSE'等方法進行Fuzzing Test



# Usage
## Step1:設定參數檔rtsp.conf
1.RHOST改成設備IP address
2.RPORT為RTSP的服務PORT。(RTSP協定預設為554)
3.STARTSIZE為模糊測試開始時最初所塞的字元長度
4.ENDSIZE為模糊測試所塞的字元長度的最大長度
5.STEPSIZE為模糊測試過程中每次遞增的字元數量
6.JUNK和DELAY欄位使用預設即可。
7.SERVERPATH為RTSP的uri路徑，例如URL為=>RTSP://192.168.1.56/Stream0，Stream0就是我們的SERVERPATH參數
8.SESSION欄位若是設備需要帳號密碼驗證時，必須給予的參數，否則Fuzzing過程中Server會一直回應401 Unauthorized!
9.MSFPATTERN保持預設為ON不需更改，此模式為讓模糊測試執行時會隨機產生payload，就不會只產生不同數量的JUNK字元(ex.AAAAAAAAAAAA)
10.STOPAFTER為模糊測試的測試筆數，規範門檻為10萬筆。

Example:
```bash=
[rtspfuzz]
#IP or Host name of the Remote host
RHOST : 192.168.1.56

#Service port Default is 554
RPORT : 554

#Starting size of JUNK 
STARTSIZE : 20

#End size of junk
ENDSIZE : 100

STEPSIZE : 20

#Junk Bytes to USE (Don't use more than one character at a time like AAAA   BBBB).
JUNK : A

#Time Delay in Seconds between two requests 
DELAY : 0

#Server PATH For Ex. http://www.mystreamingserver.com/myvideo
SERVERPATH : stream0

#This session ID will be used when session ID is required for Communication
SESSION : 467466BB2663D5A2F5CB270008EE01

#Use Metasploit pattern for fuzzing
#if its ON then it will use metasploit pattern as junk data for fuzzing instead of AAA/BBB etc etc
#using metasploit pattern when fuzzing helps to find offset
#Warning:Turning this feature on may take some extra time for fuzzing.

MSFPATTERN : ON
STOPAFTER : 1000000
```


## STEP2
執行程式
```
python rtspfuzz.py
```
## STEP3
程式執行完成後

打開log.txt確認測試過程中完整性，檢查測試筆數是否有達到10萬筆或八小時的標準

# Reference
維基百科:https://zh.wikipedia.org/wiki/%E5%8D%B3%E6%99%82%E4%B8%B2%E6%B5%81%E5%8D%94%E5%AE%9A
ITEF RFC-2326文件:https://www.ietf.org/rfc/rfc2326.txt