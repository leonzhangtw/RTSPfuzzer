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

5.STEPSIZE為模糊測試過程中每次遞增的字元數量(目前採用Random、此項設定目前不使用)

6.JUNK和DELAY欄位使用預設即可。

7.SERVERPATH為RTSP的uri路徑，例如URL為=>RTSP://192.168.1.56/Stream0，Stream0就是我們的SERVERPATH參數

8.SESSION欄位若是設備需要帳號密碼驗證時，必須給予的參數，否則Fuzzing過程中Server會一直回應401 Unauthorized!

9.MSFPATTERN保持預設為ON不需更改，此模式為讓模糊測試執行時會隨機產生payload，就不會只產生不同數量的JUNK字元(
ex.AAAAAAAAAAAA)，目前都採用MSFPATTERN產生Pattern。

10.STOPAFTER為模糊測試的測試筆數，目前規範門檻為10萬筆。

11.TYPE請根據服務設定TCP或UDP

12.RTSP認證相關資訊
Authorization : IPCam是否有帳號認證(Authorization Digest)，填Y/N，選擇Y時必須確認下列五項資訊設定正確。
USERNAME : 帳號
PASSWORD : 密碼
REALM : RTSP(選填，可先側錄正常封包觀察是否需填入指定值)
NONCE : 0000040dY892418598785d2a2304a74adf22f6098f2792(通常會隨機產生，Fuzz可自己選擇要設定什麼。)
TARGETURL : RTSP資源的URL

13.DEBUG參數設Y時，會顯示更多Payload的資訊，可以幫助找到有問題的Payload





Example:
```bash=
[rtspfuzz]
#IP or Host name of the Remote host
RHOST : 127.0.0.1

#Service port Default is 554
RPORT : 554

#Starting size of JUNK 
STARTSIZE : 5

#End size of junk
ENDSIZE : 100

STEPSIZE : 1

#Junk Bytes to USE (Don't use more than one character at a time like AAAA   BBBB).
JUNK : A

#Time Delay in Seconds between two requests 
DELAY : 1

#Server PATH For Ex. http://www.mystreamingserver.com/myvideo
SERVERPATH : stream0
#467466BB2663D5A2F5CB270008EE01
#This session ID will be used when session ID is required for Communication
SESSION : 467466BB2663D5A2F5CB270008EE01

#Use Metasploit pattern for fuzzing
#if its ON then it will use metasploit pattern as junk data for fuzzing instead of AAA/BBB etc etc
#using metasploit pattern when fuzzing helps to find offset
#Warning:Turning this feature on may take some extra time for fuzzing.

MSFPATTERN : ON
# total fuzzing test case 
STOPAFTER : 1000000

# service is using TCP or UDP
TYPE : TCP

# RTSP Authorization
AUTHORIZATION : Y
USERNAME : admin
PASSWORD : password
REALM : RTSP
NONCE : 0000040dY892418598785d2a2304a74adf22f6098f2792
TARGETURL : rtsp://192.168.1.56:554/stream0


# DEBUG mode
DEBUG : Y

```


## STEP2
執行程式
```=bash
python rtspfuzz.py rtsp.conf
```
## STEP3
程式執行完成後

打開./output/RTSP_Result.csv確認測試過程中完整性，檢查測試筆數是否有達到10萬筆或八小時的標準

# Reference
維基百科:https://zh.wikipedia.org/wiki/%E5%8D%B3%E6%99%82%E4%B8%B2%E6%B5%81%E5%8D%94%E5%AE%9A
ITEF RFC-2326文件:https://www.ietf.org/rfc/rfc2326.txt
