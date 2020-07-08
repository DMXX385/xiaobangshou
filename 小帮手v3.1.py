import requests
import json
from datetime import datetime, timedelta
import time
from retrying import retry
import base64
import os
import rsa
from hashlib import md5

#下面三个参数依次为账号、密码和每日上报时间#
mobile = '18888888888'
password = '88888888'
report_time = '00:20:00'
#########################################
CaptchaID = ''
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:ECDHE:!COMPLEMENTOFDEFAULT"
requests.packages.urllib3.disable_warnings()
my_headers = {
    'user-agent':
    'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Mobile Safari/537.36'
}


class Chaojiying_Client(object):
    def __init__(self, username, password, soft_id):
        self.username = username
        password = password.encode('utf8')
        self.password = md5(password).hexdigest()
        self.soft_id = soft_id
        self.base_params = {
            'user': self.username,
            'pass2': self.password,
            'softid': self.soft_id,
        }
        self.headers = {
            'Connection':
            'Keep-Alive',
            'User-Agent':
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)',
        }

    def PostPic(self, im, codetype):
        """
        im: 图片字节
        codetype: 题目类型 参考 http://www.chaojiying.com/price.html
        """
        params = {
            'codetype': codetype,
        }
        params.update(self.base_params)
        files = {'userfile': ('ccc.jpg', im)}
        r = requests.post('http://upload.chaojiying.net/Upload/Processing.php',
                          data=params,
                          files=files,
                          headers=self.headers)
        return r.json()

    def ReportError(self, im_id):
        """
        im_id:报错题目的图片ID
        """
        params = {
            'id': im_id,
        }
        params.update(self.base_params)
        r = requests.post(
            'http://upload.chaojiying.net/Upload/ReportError.php',
            data=params,
            headers=self.headers)
        return r.json()


class Xiaobs():
    def __init__(self):
        self.mobile = mobile
        self.password = password
        self.report_time = password
        self.CaptchaID = ''
        self.pubkey_str = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgZmNj7QvhbpgdqxN7ZCR+r874KZb/qRvlHRieJJREH+i5/hPbpPH5KheEFxoo7nyAkPIcQYPshHvC4UJBe1HrHjdhjFnMA967aebBtioXBOB0qR4ql0DtWA0PrJWtDABeTpPXedqmzMcYIxr1Wq/viIPsjCHRiyRx6mhYqT5P6wIDAQAB'

    def retry_if_io_error(e):  #定义重试机制
        return isinstance(e, TimeoutError)

    def _str2key(self, s):
        # 对字符串解码
        b_str = base64.b64decode(s)

        if len(b_str) < 162:
            return False

        hex_str = ''

        # 按位转换成16进制
        for x in b_str:
            h = hex(x)[2:]  #10进制转换成16进制
            h = h.rjust(2, '0')  #返回指定长度2左填充0的字符串
            hex_str += h

        # 找到模数n和指数e的开头结束位置
        m_start = 29 * 2
        e_start = 159 * 2
        m_len = 128 * 2
        e_len = 3 * 2

        modulus = hex_str[m_start:m_start + m_len]
        exponent = hex_str[e_start:e_start + e_len]

        return modulus, exponent  #返回切片后的字符串形式的n和e

    def rsa_encrypt(self, s, pubkey_str):
        '''
        rsa加密
        :param s:
        :param pubkey_str:公钥
        :return:
        '''
        key = Xiaobs()._str2key(pubkey_str)
        modulus = int(key[0], 16)
        exponent = int(key[1], 16)
        pubkey = rsa.PublicKey(modulus, exponent)
        return base64.b64encode(rsa.encrypt(s.encode(), pubkey)).decode()

    @retry(stop_max_attempt_number=10,
           wait_random_min=500,
           wait_random_max=2000)
    def getCaptcha(self, CaptchaID):  #获取验证码
        url = 'https://asst.cetccloud.com/oort/oortcloud-sso/captcha/v1/' + CaptchaID + '.png'
        response = requests.get(url, headers=my_headers, verify=False)
        if len(response.content) > 800:
            print('验证码获取成功')
            Captcha = response.content
        else:
            raise Exception('验证码获取失败')
        chaojiying = Chaojiying_Client('18888888888', '88888888', '888888')
        CaptchaStr = (chaojiying.PostPic(Captcha, 1902))
        pic_str = CaptchaStr['pic_str']
        pic_id = CaptchaStr['pic_id']
        if pic_str == '':
            print('无可用题分')
        elif len(pic_str) != 6:
            chaojiying.ReportError(pic_id)
            print('验证码解析失败')
            print(CaptchaStr)
            raise TimeoutError('验证码解析失败')
        else:
            return (pic_str, pic_id)

    @retry(stop_max_attempt_number=10,
           wait_random_min=500,
           wait_random_max=2000)
    def login(self,
              CaptchaID=None,
              CaptchaStr=None,
              captcha=None):  #登陆，分为带验证码不带验证码两种登陆方式，返回response
        password = Xiaobs().rsa_encrypt(self.password, self.pubkey_str)
        url = 'https://asst.cetccloud.com/ncov/login'
        if captcha == None:
            data = {"mobile": mobile, "password": password, "client": "h5"}
            response = requests.post(url,
                                     data=data,
                                     headers=my_headers,
                                     verify=False)
        elif captcha == True:
            data = {
                "mobile": mobile,
                "password": password,
                "client": "h5",
                "captchaID": CaptchaID,
                "codeNo": CaptchaStr
            }
            response = requests.post(url,
                                     data=data,
                                     headers=my_headers,
                                     verify=False)
        return response

    def parse_response(self, response, pic_id=None):  #检测登陆后返回数据，排除三种错误
        chaojiying = Chaojiying_Client('18888888888', '88888888', '888888')
        r = json.loads(response)
        if r["success"] == True:
            accessToken = r['data']['userInfo']['accessToken']
            return accessToken
        else:  #r["success"] == False:
            if r["message"] == '验证码错误':  #验证码错误时，如果传入pic_id参数，则上报错误，如未传入pic_id参数，则pass
                print('验证码错误')
                if pic_id == None:
                    pass
                else:
                    chaojiying.ReportError(pic_id)
                CaptchaID = r['data']['CaptchaID']
                CaptchaStr, pic_id = Xiaobs().getCaptcha(CaptchaID)
                response2 = Xiaobs.login(self,
                                         CaptchaID,
                                         CaptchaStr,
                                         captcha=True)
                return Xiaobs().parse_response(
                    response2.text, pic_id=pic_id)  #循环，直到返回accessToken
                #raise Exception('验证码解析失败')
            elif r["message"] == '账号未注册':
                print('账号未注册')
                return os._exit(0)
            elif '账号或密码错误' in r["message"]:
                print(r["message"])
                return os._exit(0)
            else:
                print(response)
                print('未知错误')
                return os._exit(0)

    @retry(retry_on_exception=retry_if_io_error,
           stop_max_attempt_number=10,
           wait_random_min=500,
           wait_random_max=2000)
    def posttemp(self):
        r = Xiaobs().login()
        accessToken = Xiaobs().parse_response(r.text)
        url2 = 'https://asst.cetccloud.com/oort/oortcloud-2019-ncov-report/2019-nCov/report/reportstatus'
        data2 = {"phone": mobile, "accessToken": accessToken}
        response2 = requests.post(url2,
                                  data=json.dumps(data2),
                                  headers=my_headers,
                                  verify=False)
        uid = json.loads(response2.text)['data']['uid']
        url3 = 'https://asst.cetccloud.com/oort/oortcloud-2019-ncov-report/2019-nCov/report/everyday_report'
        #url3='http://asst.cetccloud.com/oort/oortcloud-2019-ncov-report/2019-nCov/report/edit_everyday_report'
        data3 = {
            "phone": mobile,
            "Traffic_data": {
                "bike": 0,
                "bike_way": "",
                "bus": 0,
                "bus_number": "",
                "car": 0,
                "car_way": "",
                "metro": 0,
                "metro_number": "",
                "other": 0,
                "other_way": "",
                "walk": 0,
                "walk_way": "",
                "phone": mobile
            },
            "physical_data": {
                "type1": 0,
                "type1_state": "0",
                "type2": 0,
                "type3": 0,
                "type4": 0,
                "type5": 0,
                "type6": 0,
                "type7": 0,
                "type7_state": "",
                "phone": mobile
            },
            "track_data": {
                "tracks":
                "[{\"area\":\"中国-#-研究所\",\"start\":\"1583800400000\",\"end\":\"1583843500000\"}]",
                "phone": mobile
            },
            "work_way": 0,
            "touch": 0,
            "accessToken": accessToken,
            "uid": uid
        }
        response3 = requests.post(url3,
                                  data=json.dumps(data3),
                                  headers=my_headers,
                                  verify=False)
        print(response3.text)
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        Xiaobs.starttime(self)

    def starttime(self):  #定时24小时
        new_time = datetime.now()
        next_time = new_time + timedelta(days=+1)
        next_year = next_time.year
        next_month = next_time.month
        next_day = next_time.day
        next_time = datetime.strptime(
            str(next_year) + '-' + str(next_month) + '-' + str(next_day) +
            ' ' + report_time, '%Y-%m-%d %H:%M:%S')
        while datetime.now() < next_time:
            print('\r现在时间{}，{}后上报'.format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                str(next_time - datetime.now())[:-7],
            ),
                  end='')
            time.sleep(1)
        Xiaobs.posttemp(self)


def main():
    print('每日上报时间:' + report_time)
    try:
        Xiaobs().posttemp()
    except:
        return Xiaobs().posttemp()


main()