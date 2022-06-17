from ipwhois import IPWhois
Finaloutput=[]
def getipinformation(ip):
    global Finaloutput
    obj=IPWhois(ip)
    res=obj.lookup_whois()
    for i in res:
        if isinstance(res[i], list):
            print(f"\n\n\n=============== {i} ===============\n")
            Finaloutput.append(f"\n\n\n=============== {i} ===============\n")
            for j in res[i]:
                if isinstance(j, dict):
                    for k in j:
                        print(f"{k} ==> {j[k]}")
                        Finaloutput.append(f"{k} ==> {j[k]}\n")
                else:
                    print(f"{j}\n")
                    Finaloutput.append(f"{j}\n")
        
        elif isinstance(res[i], dict):
            print(f"\n\n\n=============== {i} ===============\n")
            Finaloutput.append(f"\n\n\n=============== {i} ===============\n")
            for j in res[i]:
                Finaloutput.append(f"{j} ==> {res[i][j]}\n")
                print(f"{j} ==> {res[i][j]}\n")
        
        else:
            
            Finaloutput.append(f"\n\n=============== {i} ===============\n")
            print(f"\n\n=============== {i} ===============\n")
            print(f"{i} ==> {res[i]}")
            Finaloutput.append(f"{i} ==> {res[i]}")

    # pprint(res)
    print("\n\n\n########################### lookup_rdap ############################\n")
    Finaloutput.append("\n\n\n########################### lookup_rdap ############################\n")
    rese=obj.lookup_rdap()
    for i in rese:
        if isinstance(rese[i], list):
            print(f"\n\n\n=============== {i} ===============\n")
            Finaloutput.append(f"\n\n\n=============== {i} ===============\n")
            print("list")
            Finaloutput.append("list")
            for j in rese[i]:
                if isinstance(j, dict):
                    for k in j:
                        print(f"{k} ==> {j[k]}")
                        Finaloutput.append(f"{k} ==> {j[k]}")
                else:
                    print(f"{j}\n")
                    Finaloutput.append(f"{j}\n")
        
        elif isinstance(rese[i], dict):
            print(f"\n\n\n=============== {i} ===============\n")
            Finaloutput.append(f"\n\n\n=============== {i} ===============\n")
            
            
            for j in rese[i]:
                print(f"{j} ==> {rese[i][j]}\n")
                Finaloutput.append(f"{j} ==> {rese[i][j]}\n")
        
        else:
            
            print(f"\n\n=============== {i} ===============\n")
            Finaloutput.append(f"\n\n=============== {i} ===============\n")
            
            print(f"{i} ==> {res[i]}")
            Finaloutput.append(f"{i} ==> {res[i]}")
    return Finaloutput