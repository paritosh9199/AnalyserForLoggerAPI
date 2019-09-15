import json


class Analyser:
    def __init__(self, file="./data.json"):
        self.file = file
        self.cacheFirstVisit()

    def getAllData(self):
        ds = {}
        if self.file:
            with open(self.file, 'r') as f:
                ds = json.load(f)
        return ds

    def printAllData(self):
        ds = {}
        if self.file:
            with open(self.file, 'r') as f:
                ds = json.load(f)

        for d in ds['logs']:
            print(d.get('_id'))
            print(d.get('timestamp'))
            print(d.get('message_type'))
            print(d.get('ip'))
            print(d.get('route_path'))
            print(d.get('hash'))
            print('------------------------------------------')

    def cacheFirstVisit(self):
        # Complexity: O(m*n) or ~O(n^2)
        self.cache_firstVisitData = []
        data = self.getAllData()
        for i in data['logs']:
            def f(a): return a['ip'] == i['ip'] and a['hash'] == i['hash']
            if(len(list(filter(f, self.cache_firstVisitData))) <= 0):
                d = {'ts': i['timestamp'], 'hash': i['hash'], 'ip': i['ip']}
                self.cache_firstVisitData.append(d)

    def getFirstVisitCache(self):
        return self.cache_firstVisitData

    def compareCachedFirstArray(self,a):
        for i in self.cache_firstVisitData:
            if(i['hash'] == a['hash']):
                if(i['ts'] == a['timestamp']):
                    return 1
                elif(i['ts'] >= a['timestamp']):
                    return 0
                else:
                    return 2

    def analyseByDuration(self, duration=60*60*1000):
        # o/p: [{ts-start:t1, ts-end:t2, new:x, old:y}]
        analysis = []
        d = self.getAllData()
        sorted_list = sorted(d['logs'], key=lambda i: i['timestamp'])

        start_time = d['logs'][0]['timestamp'] - duration/2
        end_time = d['logs'][len(d['logs'])-1]['timestamp'] + duration/2

        # steps = int((end_time-start_time)/duration)+1
        stepTime = start_time
        while(stepTime < end_time+duration/2):
            t1 = stepTime
            t2 = stepTime + duration
            analysis.append({"t1": t1, "t2": t2, "new": 0, "old": 0})

            for i in d['logs']:
                if(i.get('timestamp') >= t1 and i.get('timestamp') <= t2):
                    # def f(
                    #     a): return a['ip'] == i['ip'] and a['hash'] == i['hash'] and a['ts'] >= t1 and a['ts'] < t2
                    if(len(list(filter(compareCachedFirstArray, self.cache_firstVisitData))) == 1):
                        analysis[len(analysis) - 1]['old'] += 1
                    else:
                        analysis[len(analysis) - 1]['new'] += 1
                else:
                    break
            stepTime += duration

        return analysis

