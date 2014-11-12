import re
import chardet
import time
import logging
import sys
import xmlrpclib
logging.basicConfig(level=logging.DEBUG)

#we're working entirely with virtual addresses

#G is the referene to the visualization library
server = xmlrpclib.Server('http://localhost:20738/RPC2')
G = server.ubigraph


#dump ascii values to another file
fasci = open("./asci_interpret","w")

#this takes a file as an input (#.txt in all use cases in this program) and
#populates the pagetables structure
def page_analyze(file_name):

    fpage = open(file_name, 'r')           # open the file that has the page	
    page_name=""
    page_line_count = 0                    # count zero means the start of the page
    for line in iter(fpage.readline, ''):  # read everyline of the page

        if(line == "\n"):             # if the line just has a new line continue
            continue

        nums = line.split()           # split the line into multiple words 
        mem_pattern = "Memory"        # if the dump has a "Memory" just ignore
        if(mem_pattern in line):       
            continue
          
        value1 = nums[4].decode("hex") + nums[3].decode("hex") + nums[2].decode("hex") + nums[1].decode("hex")
        encoding = chardet.detect(value1)  # check if it makes sense in the ascii
        if encoding['encoding'] == 'ascii':
            clean = re.sub('[^\s!-~]', '', value1)

            print >> fasci,clean[::-1]  # remove the control characters when printing to asci_interpet (regex applied on each line of fasci)

        #example: wordList = 7f7adfeb4000 dead0000 beef0000 f00d0000 cafe0000
        wordList = re.sub("[^\w]", " ",  line).split()
        #example refw = 7f7adfeb4000
        refw = wordList[0]

        if page_line_count == 0 :	                
            page_name = refw   # initialize the page name when page line count is 0
            page_list.append(page_name)

        # store the entire line as a function of page_name _ address         
        #page name + the first eight bytes
        #example: data_for_line = 7f7adfeb4000_dead0000
        data_for_line = page_name + "_" + wordList[0]

        ptr1 = wordList[2]+wordList[1]
        ptr2 = wordList[4]+wordList[3]

        pagetables[data_for_line] = wordList[1] + "  " + wordList[2] + "  " + wordList[3] + "  " + wordList[4]          

        # compare the refw and ptr1 and ptr2 to determine if they look like pointers
	
        subaddr = refw[0:5]  # get the lower order address (it should occur in the lower address range
        ptr1addr = ptr1[4:9] # get the lower order address to compare for the first pointer
        ptr2addr = ptr2[4:9] # get the lower order address to compare for the second pointer         
	       
        if ptr1addr in subaddr :
            # store it in the page related to it's data structure
            if page_name in pagetables.keys():
                pagetables[page_name].append(ptr1)
            else:
                pagetables[page_name] = [ptr1]

        if ptr2addr in subaddr :
            # store it in the page related to it's data structure
            if page_name in pagetables.keys():
                pagetables[page_name].append(ptr2)
            else:
                pagetables[page_name] = [ptr2]
	         
        # increment the page line count after every line is processed
        page_line_count = page_line_count + 1

    value = nums[1].decode("hex") + nums[0].decode("hex") + nums[3].decode("hex") + nums[2].decode("hex")
    encoding = chardet.detect(value)


def add_nodes_and_edges(x):
    if(len(x) >= 2):
        previous_ptr = None
        for i in range (0, len(x)):
            ptr = G.new_vertex()
            if previous_ptr != None:
                G.new_edge(ptr, previous_ptr)


#**********************
#Here begins execution
#**********************

if len(sys.argv) != 2:
    print "Invalid arguments, proper usage: python heap_anal_ptr_anal_updated_visual_pie_chart.py <filename>"
    sys.exit(0)

print "len(sys.argv) = ", len(sys.argv)
print "sys.argv = ", sys.argv
print "sys.argv[1] = ", sys.argv[1]
filename = sys.argv[1]

#contain all the lines in all the pages
pagetables = dict()

#contains the start of each page
page_list = list()

#put all the lines in here before adding to pagetables
cur_buf=""

count=0;
with  open('./' + filename,'r') as fptr:
    for line in iter(fptr.readline, ''):
        if ("END OF PAGE" not in line):
            cur_buf += line
        else :
            file_name = str(count) + ".txt"
            fptr = open(file_name,"w+")
            fptr.write(cur_buf) 
            cur_buf = ""
            fptr.close()
            page_analyze(file_name)                      
            count = count + 1

print "We now have all the pages indexed"

count_of_ptrs = 0
count_pages = 0
#this loop calculates the total nuumber of pointers (and is useful for printing)
for page in page_list:
    #print(page, len([item for item in value if item]))
    count_pages = count_pages + 1   
    if page in pagetables.keys():
        value = pagetables[page]
        print(page, len(value))                  
        count_of_ptrs = count_of_ptrs + len(value)


# 7f1b1e4e9580

# stats collection varibales
# ptr not existant in the collection at the first go
ptr_non_existant_ctr0_dict = dict()
ptr_non_existant_ctr0 = 0
# ptr not existant in the collection after few traversals
ptr_non_existant_ctrn_dict = dict()
ptr_non_existant_ctrn = 0
# ptr link list and pointing to the data in the end
ptr_link_list_ctrn_data_dict = dict()
ptr_link_list_ctrn_data = 0 
# ptrs which are non 8 byte aligned and with ctr 0
ptr_non8_ctr0_dict = dict()
ptr_non8_ctr0 = 0
# ptr link list and poiting to non 8 byte aligned pointer in the end
ptr_non8_ctrn_dict = dict()
ptr_non8_ctrn = 0
# ptrs having a circular links with count n
ptr_circular_cntn_dict = dict()
ptr_circular_cntn = 0
# ptr which are poting to itself
ptr_circular_cnt0_dict = dict()
ptr_circular_cnt0 = 0
# ptrs which lead to partial circular link list i.e. loop in the middle
ptr_partial_circular_dict = dict()
ptr_partial_circular = 0
# ptrs which have data immediately
ptr_link_list_ctr0_data_dict = dict()
ptr_link_list_ctr0_data = 0

unique_ptr_count = 0
fptrc = open("./ptr_analysis","w")
seenu = 0
mis_count = 0
seen_ptr = []
for key, value in pagetables.iteritems() :
    if type(value) is list:
        for value_inst in value:
            orig_ptr  = value_inst
            input_ptr = value_inst[4:16]
            if input_ptr in seen_ptr:
                seenu = seenu + 1
                continue  
            traverse_array = []
            circle_count = 0
            while (1):               
                unique_ptr_count = unique_ptr_count + 1
	        traverse_array.append(input_ptr)        
                seen_ptr.append(input_ptr)              
	        #mask the last 12 bits to get the page name
		ref = input_ptr[0:5]
		in_ptr = input_ptr[0:9]
		in_ptr = in_ptr + "000"  # converted the pointer to  7f1b1e4e9000
		make_key = in_ptr+ "_"+input_ptr # recovered the key to hash into

                new = list(make_key)
                new[len(make_key)-1] = '0'
                new = "".join(new)
                make_key = new
                try:
                    line = pagetables[make_key]    # get the line
                except KeyError:
                    if (circle_count == 0):
                        ptr_non_existant_ctr0 = ptr_non_existant_ctr0 + 1
                        print >> fptrc,"Pointer/pointer like data non existent in the collection: ",orig_ptr                              
                    if (circle_count > 0):
                        ptr_non_existant_ctrn = ptr_non_existant_ctrn + 1
                        if len(traverse_array) in ptr_non_existant_ctrn_dict.keys():
                            ptr_non_existant_ctrn_dict[len(traverse_array)].append(traverse_array)
                        else:
                            ptr_non_existant_ctrn_dict[len(traverse_array)] = [[traverse_array]]
                        print >> fptrc,"The end pointer was non existent in the collection: ",traverse_array[0],"count: ",circle_count

                    traverse_array.pop()

                    mis_count = mis_count + 1
                    add_nodes_and_edges(traverse_array)
                    break

                ptr_list = re.sub("[^\w]", " ",  line).split()  #split the line

                ptr1 = ptr_list[1]+ptr_list[0]
                ptr2 = ptr_list[3]+ptr_list[2]

                ptr1addr = ptr1[4:9] # get the lower order address to compare for the first pointer
                ptr2addr = ptr2[4:9] # get the lower order address to compare for the second pointer

                if (input_ptr[len(input_ptr)-1] == '0' and ref not in ptr1addr):
                    if(circle_count == 0):
                        ptr_link_list_ctr0_data = ptr_link_list_ctr0_data + 1
                    elif(circle_count > 0):
                        ptr_link_list_ctrn_data = ptr_link_list_ctrn_data + 1
                        if len(traverse_array) in ptr_link_list_ctrn_data_dict.keys():
                            ptr_link_list_ctrn_data_dict[len(traverse_array)].append(traverse_array)
                        else:
                            ptr_link_list_ctrn_data_dict[len(traverse_array)] = [[traverse_array]]

                    print "linear link list:",traverse_array,len(traverse_array)
                    add_nodes_and_edges(traverse_array)
                    print >> fptrc,"ptr =",orig_ptr,"linear link list","count :",circle_count
                    break

                #consider the appropriate pointer to move forward with     
                if (input_ptr[len(input_ptr)-1] == '8' and ref not in ptr2addr):
                    if(circle_count == 0):
                        ptr_link_list_ctr0_data = ptr_link_list_ctr0_data + 1
                    elif(circle_count > 0):
                        ptr_link_list_ctrn_data = ptr_link_list_ctrn_data + 1
                        if len(traverse_array) in ptr_link_list_ctrn_data_dict.keys():
                            ptr_link_list_ctrn_data_dict[len(traverse_array)].append(traverse_array)
                        else:
                            ptr_link_list_ctrn_data_dict[len(traverse_array)] = [[traverse_array]]

                    print >> fptrc,"ptr =",orig_ptr,"linear link list","count :",circle_count
                    print"linear link list:",traverse_array, len(traverse_array)
                    add_nodes_and_edges(traverse_array)
                    break

                # consider the appropriate pointer to move foraward with
                if ((ref in ptr1addr or ref in ptr2addr) and input_ptr[len(input_ptr)-1]!='0' and input_ptr[len(input_ptr)-1]!='8'):
                    if(circle_count == 0):
                        print >> fptrc, "non 8 byte aligned pointer",orig_ptr," ",input_ptr," ",circle_count
                        ptr_non8_ctr0 = ptr_non8_ctr0 + 1
                        break
                    elif(circle_count > 0):
                        ptr_non8_ctrn = ptr_non8_ctrn + 1
                        if len(traverse_array) in ptr_non8_ctrn_dict.keys():
                            ptr_non8_ctrn_dict[len(traverse_array)].append(traverse_array)
                        else:
                            ptr_non8_ctrn_dict[len(traverse_array)] = [[traverse_array]]

                        print >> fptrc, "non 8 byte aligned pointer",orig_ptr," ",input_ptr," ",circle_count
                        add_nodes_and_edges(traverse_array)
                        break               

                prev_ptr = input_ptr
                length = len(input_ptr)
                if(input_ptr[length - 1] == '0'):
                    if(ptr1addr in ref):
                        input_ptr = ptr1
                        input_ptr = input_ptr[4:(len(ptr1))]

                elif(input_ptr[length - 1] == '8'):
                    if(ptr2addr in ref):
                        input_ptr = ptr2
                        input_ptr = input_ptr[4:(len(ptr2))]

                if (input_ptr in traverse_array):
                    if input_ptr in traverse_array[0] and circle_count > 0:
                        print >> fptrc,"circular link list circle_depth: ",traverse_array[0]," ",orig_ptr," ",circle_count
                        ptr_circular_cntn = ptr_circular_cntn + 1
                        if len(traverse_array) in ptr_circular_cntn_dict.keys():
                            ptr_circular_cntn_dict[len(traverse_array)].append(traverse_array)
                        else:
                            ptr_circular_cntn_dict[len(traverse_array)] = [[traverse_array]]

                    elif(circle_count == 0 and (traverse_array[0] in input_ptr)):
                        print >> fptrc,"pointer pointing to itself",traverse_array[0]," ",orig_ptr," ",circle_count

                        ptr_circular_cnt0 = ptr_circular_cnt0 + 1
                    elif(circle_count > 0):
                        traverse_array.append(input_ptr)
                        ptr_partial_circular = ptr_partial_circular + 1
                        if len(traverse_array) in ptr_partial_circular_dict.keys():
                            ptr_partial_circular_dict[len(traverse_array)].append(traverse_array)
                            print >> fptrc,"partial circular link list:",traverse_array
                        else:
                            ptr_partial_circular_dict[len(traverse_array)] = [[traverse_array]]
                            print >> fptrc,"partial circular link list:",traverse_array


                    print >> fptrc,"circular link list:",traverse_array, len(traverse_array)
                    traverse_array.append(input_ptr)
                    add_nodes_and_edges(traverse_array)
                    break

                # this is done because it's the extension of the already existing linked list, trying to be cautius here
                if input_ptr in seen_ptr:                           
                    if("000000000000" not in input_ptr):
                        print "JUNK:", traverse_array, "INPUT_PTR", input_ptr
                        traverse_array.append(input_ptr)
                    add_nodes_and_edges(traverse_array)
                    break

                circle_count = circle_count + 1


print "total pointers is",count_of_ptrs
print "mis_count is",mis_count
print "count_pages : ",count_pages
print "unique ptr count:",unique_ptr_count
print "redundant ptr count:",(count_of_ptrs - unique_ptr_count)	
print "ptr not existant in the collection at the first go",ptr_non_existant_ctr0	            
print "ptr not existant in the collection after few traversals:",ptr_non_existant_ctrn
print "ptr link list and pointing to the data in the end:",ptr_link_list_ctrn_data
print "ptrs which have data immediately:",ptr_link_list_ctr0_data
print "ptrs which are non 8 byte aligned and with ctr 0",ptr_non8_ctr0
print "ptr link list and pointing to non 8 byte aligned pointer in the end",ptr_non8_ctrn
print "ptrs having a circular links with count n",ptr_circular_cntn
print "ptr which are poting to itself",ptr_circular_cnt0
print "ptrs which lead to partial circular link list i.e. loop in the middle",ptr_partial_circular
print "Note: This analyzes direct pointers only and relations in a structure is not analyzed"



#known bugs
# for the pointers which have first 4 bytes as Os, Pointers can be misrepresented. Pointer comparison parameters should change 
# for such pointers
# differentiate different data structures with different colors
# shift to using d3js for better color coding as d3py is almost deprecated
# establish directions to the pointers. We are currently not doing that. Things that might look like a tree needn't be a tree but
# the visualisation make you believe it's a tree
