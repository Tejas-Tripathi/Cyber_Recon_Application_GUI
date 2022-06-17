import whois


def is_registered(domain_name):
    try:
        w = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(w.domain_name)

FinalOutput=[]
# target="https://virusshare.com/"

def domainoutput(urldata):
    global FinalOutput
    if is_registered(urldata):
        alpha=whois.whois(urldata)
    else:
        FinalOutput.append("invalid Domain recheck and enter again")
        print("invalid Domain recheck and enter again")
        alpha={'INVALID DOMAIN': "Please recheck the domain name and retry"}

    for i in alpha:
        print(f"\n\n\n============== {i} ==============\n")
        FinalOutput.append(f"\n\n============== {i} ==============\n")
        if isinstance(alpha[i], list):
            for j in alpha[i]:
                FinalOutput.append(f"\t{j}\n")
                print(f"\t{j}\n")
        else:
            print(f"\t{i} ==> {alpha[i]}")
            FinalOutput.append(f"\t{i} ==> {alpha[i]}")
    return FinalOutput
