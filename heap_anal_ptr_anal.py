import re
import chardet
import time
fasci = open("./asci_interpret","w")
def page_analyze(file_name):
	# open the file that has the page
	fpage = open(file_name, 'r')
	
	page_name=""
	count = 0
	for line in iter(fpage.readline, ''):
                 #print line
	         # split the line into words
                 if(line == "\n"):
                     continue
                 
                 # just printing the asci equivalent of every line
                 nums = line.split()                
                 value1 = nums[4].decode("hex") + nums[3].decode("hex") + nums[2].decode("hex") + nums[1].decode("hex")
                 encoding = chardet.detect(value1)
                 if encoding['encoding'] == 'ascii':
                          clean = re.sub('[^\s!-~]', '', value1)
                          print >> fasci,clean[::-1]

	         wordList = re.sub("[^\w]", " ",  line).split()
	         refw = wordList[0]
	         
	         if count == 0 :
	                # initialize page_name to the first word
	                page_name = refw
                        page_list.append(page_name)
	
	         # store the entire line as a function of page_name _ address         
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
	         
	         # increment the count after every line is processed
	         count = count + 1
	
	# print all the key value pairs. 
	
	#for key, value in pagetables.iteritems() :
	#    print key, value
	
	# for now it should just be one key
	#for key in pagetables.keys():
	#    print key
	
	nums = pagetables['7f1b1e49f000_7f1b1e49f010'].split()
	value = nums[1].decode("hex") + nums[0].decode("hex") + nums[3].decode("hex") + nums[2].decode("hex")
	encoding = chardet.detect(value)
	if encoding['encoding'] == 'ascii':
	    #print 'string is in ascii'
	    print value

def print_tree(input_key):
        
        if input_key in pagetables.keys():
            value = pagetables[input_key]      
        else:
            print "Invalid key or no values exist for this key"
            return

        while (input_key in pagetables.keys()): 
                  value = pagetables[input_key]
                  print input_key
                  # split the input_key
                  if "_" in input_key:
                           splitkeys = re.sub("[^\w]","_",input_key).split()
                           page_name = splitkeys[0]
                           line_name = splitkeys[1]
                  
                  # trying to see if the value words look like pointers
                  valuewords = re.sub("[^\w]"," ", value).split()
                  print valuewords
                  addr1 = valuewords[2] + valuewords[1]
                  addr2 = valuewords[4] + valuewords[3]
                  subaddr = line_name[0:5]
                  ptr1addr = addr1[4:9]
                  ptr2addr = addr2[4:9]
                  print subaddr
                  print ptr1addr
                  print ptr2addr
                  input_key = "NULL"
                   
                   
# create a dictionary 
pagetables = dict()
page_list = list()
#buffer_read =""
#buffer_read += fptr.read()
cur_buf=""
#print buffer_read
#for line in buffer_read.readl():
count=0;
with  open('./full_blocks','r') as fptr:
        for line in iter(fptr.readline, ''):
                if ("END OF PAGE" not in line):
                        cur_buf += line
                        #cur_buf += "\n"
                else :
                        file_name = str(count) + ".txt"
                        fptr = open(file_name,"w+")
                        fptr.write(cur_buf) 
                        cur_buf = ""
                        fptr.close()
                        page_analyze(file_name)                      
                        count = count + 1

print "here are all the pages parsed"
#for page in page_list:
#        print page
print "We now have all the pages indexed"

#input_key = raw_input ("Enter the key ")
#print ("your key is" + input_key)
value = pagetables["7f1b1e4cf000"]
print value
#print_tree(input_key)

#print out all the pointers
count_of_ptrs = 0
count_pages = 0
for page in page_list:
   #print(page, len([item for item in value if item]))     
   count_pages = count_pages + 1   
   if page in pagetables.keys():
          value = pagetables[page]
          print(page, len(value)*4)                  
          count_of_ptrs = count_of_ptrs + len(value)

           
#for key, value in pagetables.iteritems() :
#           #print key, value
#           if type(value) is not list:
#                     nums = value.split()
#                     value1 = nums[1].decode("hex") + nums[0].decode("hex") + nums[3].decode("hex") + nums[2].decode("hex")
#                     encoding = chardet.detect(value1)
#                     if encoding['encoding'] == 'ascii':
#                           print value1

# take a pointer as a input and traverse the heap

#take ptr as an input
#while (1)
#         go to the pointer location by hashing the dictionary
#         check out the value (16 bytes)
#         determine if that line contains a pointer
#         if so split the value into (2 pointers)
#         take the appropriate pointer based on the address
#         print the indirection (--->)
#         set preev as input
#         set the input as one of the pointers
#         if input is same as prev it has cyclic dependency
         
         
# 7f1b1e4e9580


fptrc = open("./ptr_analysis","w")
mis_count = 0
for key, value in pagetables.iteritems() :

   if type(value) is list:
     for value_inst in value:
       
        orig_ptr  = value_inst
        input_ptr = value_inst[4:16]
        traverse_array = []
        circle_count = 0
	while (1):
	        traverse_array.append(input_ptr)        
	        #mask the last 12 bits to get the page name
		ref = input_ptr[0:5]
		#print ref
		in_ptr = input_ptr[0:9]
		in_ptr = in_ptr + "000"  # converted the pointer to  7f1b1e4e9000
		make_key = in_ptr+ "_"+input_ptr # recovered the key to hash into

                try:
		                 line = pagetables[make_key]    # get the line
                except KeyError:
                       mis_count = mis_count + 1
                       print make_key
                       break
		ptr_list = re.sub("[^\w]", " ",  line).split()  #split the line
	
		ptr1 = ptr_list[1]+ptr_list[0]
		ptr2 = ptr_list[3]+ptr_list[2]
	
		ptr1addr = ptr1[4:9] # get the lower order address to compare for the first pointer
		ptr2addr = ptr2[4:9] # get the lower order address to compare for the second pointer
	
		if (ref not in ptr1addr and ref not in ptr2addr):
		              #print "we have hit a dead end",pagetables[make_key]
                              print >> fptrc,"ptr =",orig_ptr,"not a cycle","count :",circle_count
	                      break
		
		# consider the appropriate pointer to move foraward with
		prev_ptr = input_ptr
		length = len(input_ptr)
		if(input_ptr[length - 1] == '0'):
		                 if(ptr1addr in ref):
		                      input_ptr = ptr1
		                      input_ptr = input_ptr[4:(len(ptr1))]
		                      #print input_ptr
		                      #print pagetables[make_key]
		
		elif(input_ptr[length - 1] == '8'):
		                 if(ptr2addr in ref):
		                      input_ptr = ptr2
		                      input_ptr = input_ptr[4:(len(ptr2))]
		                      #print input_ptr
		                      #print pagetables[make_key]
		
		#print "prev_ptr is",  prev_ptr
		#print "input_ptr is", input_ptr
		#time.sleep(2)
	        if (input_ptr in traverse_array):
	                    print >> fptrc,"ptr =",orig_ptr,"count :",circle_count+1
	                    break
                circle_count = circle_count + 1
	  
         	#collect all the pointer stats
       
print "total pointers is",count_of_ptrs
print "mis_count is",mis_count
print "count_pages : ",count_pages
		            
