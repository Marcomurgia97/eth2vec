import json
import os
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from glob import glob
def rename(name):
    new_name=''
    for c in name:
        if(c=='.'):
            break
        new_name+=c
    return new_name
files=glob('experiments2/*.json')
vul_names={  "ERC20": [],
            "GasConsumption": [],
            "ImplicitVisibility": [],
            "IntegerOverflow": [],
            "IntegerUnderflow": [],
            "Reentrancy": [],
            "TimeDependency": []}

for file in files:
    name=rename(os.path.basename(file))
    f=open('../../../Desktop/eth2vec-main/bin/Label.json')
    labels = json.load(f)
    print(name)
    #Read Kam1n0 Output
    with open(file,'r') as f1:
        lines=f1.readlines() #Every line correspond to a function
        for l in lines:
            inputdata=json.loads(l) #parse text as JSON
            clones=inputdata['clones']
            vuln=[] #array of finded vulnerabilities
            names=inputdata['function']['functionName'].split('.')
            functionName=names[0]
            contractName=names[1]
            true_vulns=[]     
            info={}
            info['fname']=functionName
            name=name.replace('Composition-','')
            #If the function name doesn't exit on labels file,skip it
            try:
                for x in labels[name][contractName][functionName]:                   
                    if labels[name][contractName][functionName][x]==1:
                        true_vulns.append(x)                       

            except:
                continue
            info['true_vulns']=true_vulns
            v_list=[]
            info['clones']=len(clones)
            if len(clones)<1:
                info['vuln']=[]

            #Loop over clones and find vulnerabilities
            for c in clones:       
                filename=os.path.basename(c['binaryName']).replace('.sol','')            
                names=c['functionName'].split('.')            
                functionName=names[0]
                contractName=names[1]      
                contract=labels[filename]
                try:
                    for x in contract[contractName][functionName]:

                        if(contract[contractName][functionName][x]==1): 
                            if x not in v_list:                      
                                v_list.append(x)
                                #model_predictions[vul_names[x]]=1
                    info['vuln']=v_list
                except:
                    continue

            for v in v_list:
                if v in true_vulns:
                    vul_names[v].append(1) #True positives
                else:
                    vul_names[v].append(0) #False Positives
        
            for v in true_vulns:
                if v not in v_list:
                    vul_names[v].append(2) #False negatives
            vuln.append(info)    
                    

            print(vuln)
print(vul_names)
for vul in vul_names.keys():

    if(len(vul_names[vul])>0):

        tp=len([n for n in vul_names[vul] if n==1])
        fp=len([n for n in vul_names[vul] if n==0])
        fn=len([n for n in vul_names[vul] if n==2])
        
        if(tp>0):
            precision=tp/(tp+fp)
            recall=tp/(tp+fn)
            f1_score=tp/(tp+((fp+fn)/2))
        else:
            precision=0
            recall=0
            f1_score=0
        
       
        print(vul+' F1',f1_score)
        print(vul+' Precision',precision)
        print(vul+' RECALL',recall)
#print(labels[name]['source'])
        