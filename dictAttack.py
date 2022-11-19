# library imports
import hashlib

# initializing string
import csv
with open('dictionary.csv', newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    data = list(reader)

with open('bigList.csv', newline='') as csvfile:
    reader2 = csv.reader(csvfile, delimiter=',')
    data2 = list(reader2)

# unpacking list of lists
for i in range(len(data)):
    data[i] = (data[i][0])
# unpacking list of lists
for i in range(len(data2)):
    data2[i] = (data2[i][0])

# merging two datasets
data = list(set(data+data2))
# length of corpus of words we will hash
print(len(data))

hashObjs = [None]*len(data)
result = [None]*len(data)
for i in range(0,len(data)):
    hashObjs[i] = hashlib.md5(data[i].encode())
    result[i] = hashObjs[i].hexdigest()

# write out the hashes and their raw text to a file, new rainbow table
fields = ['rawText', 'md5Hash']
filename = "md5Rainbow.csv"
with open(filename, 'w', newline='') as csvfile:
    # creating a csv writer object
    csvwriter = csv.writer(csvfile)
    # writing the fields
    csvwriter.writerow(fields)
    # writing the data rows
    csvwriter.writerows(list(zip(data, result)))
