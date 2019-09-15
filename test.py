from main import Analyser


def main():
    a = Analyser()
    # a.printAllData()
    a.cacheFirstVisit()
    length = len(a.getAllData()['logs'])
    data = len(a.getFirstVisitCache())
    for i in a.analyseByDuration():
        print(i['new'])
        print(i['old'])
        print("==================")
    print(data, length)


if __name__ == "__main__":
    main()
