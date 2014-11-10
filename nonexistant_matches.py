# This script takes a file called ptr_nonexist, a list of pointers that are non existant in the collection
# and the proc_maps file and creates a file that has the memory address, and the process the address is within.

#import the regular expression library
import re

#basic binary search of the data
def binarySearch(ptr, data, low, high):
    if low >= high:
        return None
    mid = (low + high) / 2
    cur = data[mid]
    if cur.start <= ptr < cur.end:
        return cur
    if ptr > cur.end:
        return binarySearch(ptr, data, mid + 1, high)
    if ptr < cur.start:
        return binarySearch(ptr, data, low, mid)
    if cur.start <= ptr < cur.end:
        return data[mid]


#define our data storage object

class DataStore(object):
    def __init__(self, start, end, pid, filepath):
        self.start = start              # start address
        self.end = end                  # end address
        self.pid = pid                  # process id
        self.filePath = filepath        # file path of the element

# formatting for string output
    def __str__(self):
        return 'PID: ' + str(self.pid) + '\nStart: ' + str(self.start) + '\nEnd: ' + str(
            self.end) + '\nFile path: ' + self.filePath

    def __repr__(self):
        return repr((self.start, self.end, self.pid, self.filePath))

# how we are sorting the data, the start address of the element
def GetKey(datastore):
    return datastore.start

mem_match = open('./mem_matches', 'w')
#count the number of valid process_map lines
count = 0
#hold our process maps that we put into the data structure
data_list = []
#count the matches and misses
match_count = 0
miss_count = 0

#This opens proc_maps, converts each process to a data object, and puts it into a list
with open('./proc_maps', 'r') as maps:
    for line in maps:
        hex_values = re.findall(r'0x[0-9A-F]+', line, re.I)
        if (hex_values):
            pids = re.findall(r'\d+', line)
            data = DataStore(hex_values[0], hex_values[1], pids[0], line[-82:])
            data_list.append(data)
            count += 1
#sort the list by key = start address
data_list.sort(key=GetKey)

#open the list of nonexistant pointers binary search for where they point
with open('./ptr_nonexist') as nonexist:
    for line in nonexist:
        match = binarySearch(line, data_list, 0, count)
        if match is None:
            miss_count += 1
        else:
            mem_match.write("Pointer: " + line + str(match))
            match_count += 1
    mem_match.write('\n\n Matches: ' + str(match_count) + '\n Misses: ' + str(miss_count))
