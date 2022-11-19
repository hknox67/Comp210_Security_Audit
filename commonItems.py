# library imports
import csv
import pandas as pd 

# find shared elements
def common(lst1, lst2): 
    return list(set(lst1) & set(lst2))

# making rainbow table hash values 
df = pd.read_csv("md5Rainbow.csv") 
globalPasswordList = list(df.iloc[:,1])

# store's hashed passwords
storeDF = pd.read_csv("hackerman.csv") 
storePasswordList = list(storeDF.iloc[:,1])

# generates hash matches
e=common(storePasswordList,globalPasswordList)
globalIndex = [None]*len(e)
storeIndexpassword = [None]*len(e)

# get index of match in both tables
j = 0 
for i in e:
    globalIndex[j] = globalPasswordList.index(i)
    storeIndexpassword[j] = storePasswordList.index(i)
    j+=1

# output the cracked passwords and their accounts
crackedList = [None] * len(e)
counter = 0
for i in e:
    crackedList[counter] = [storeDF.iloc[:,0][storeIndexpassword[counter]], df.iloc[:,0][globalIndex[counter]], storeDF.iloc[:,3][storeIndexpassword[counter]], e[counter]]
    counter += 1
fields = ['username', 'rawText password', 'email address', 'md5Hash']
filename = "crackedList.csv"
with open(filename, 'w', newline='') as csvfile:
    # creating a csv writer object
    csvwriter = csv.writer(csvfile)
    # writing the fields
    csvwriter.writerow(fields)
    # writing the data rows
    csvwriter.writerows(crackedList)