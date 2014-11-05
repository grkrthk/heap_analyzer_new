#This script takes a file called ptr_nonexist, a list of pointers that are non existant in the collection and the proc_maps file and creates a file that has the memory address, and the process the address is within.

#import the regular expression library
import re
count = 0
#open file to store the matches
mem_match = open('./mem_matches', 'w')

#open the list of pointers not existing in the traversal
with open('./ptr_nonexist','r') as nonexist:
    #go through line by line
    for line in nonexist:
        #if the hex value in the line is 0x0..., skip it
        if line != "0x0000000000000000\n":
            #open the proc_maps to go through line by line
            with open('./proc_maps', 'r') as maps:
                for line2 in maps:
                    #fine all hex values within the line.  There are max three
                    #the first two values will be the start and end memory address of the process
                    hex_values = re.findall(r'0x[0-9A-F]+', line2, re.I)
                    #if we find hex values, and the hex code in the line is bigger than or equal
                    #to the start address and less than the end address, we have a match
                    if hex_values and line >= hex_values[0] and line < hex_values[1]:
                        mem_match.write("Match \n" + line + line2 + "\n")
                        count = count + 1
                        #we can break early to reduce runtime
                        break
    print str(count) + " matches. \n"
