import sys
import hashlib
import subprocess
import StringIO

import magic
import pydeep
import exiftool
import PyPDF2

from settings import *

##############################################################################
# Helper functions
##############################################################################
def run_and_get_output(*args):
    run = subprocess.Popen(args,
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    result = run.communicate()[0].strip()
    return result

##############################################################################
# Base Analysis
##############################################################################

def ssdeep_compare(ssdeep, md5, all_samples):
    # Compare ssdeep hash of file to all files in db
    # fuzzy_threshold defined in settings.py - default = 10
    # Returns matches as comma-separated MD5 hashes
    matches = []

    for sample in all_samples:
        print sample
        if md5 != sample.md5:
            print "needle", ssdeep
            print "haystack", sample.ssdeep
            fuzzy_res = pydeep.compare(ssdeep, sample.ssdeep)
            if fuzzy_res >= fuzzy_threshold:
                matches.append(sample.md5)

    return ",".join(matches)
    

def get_hashes(samplefile):
    """Helper function optimized to only require a single iteration"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    for chunk in samplefile.chunks():
         md5.update(chunk)
         sha1.update(chunk)
         sha256.update(chunk)

    # Unfortunately, fuzzyhash doesn't have a hashlib-compatible interface
    samplefile.seek(0, 0)       
    def get_fuzzy(fh):
        fuzzy = pydeep.hash_buf(fh.read())
        position = fh.seek(0, 0)
        return fuzzy
    fuzzy = get_fuzzy(samplefile)
    
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), fuzzy


def get_filetype(samplefile):
    m=magic.open(magic.MAGIC_NONE)
    m.load()
    for chunk in samplefile.chunks(chunk_size=4096):
        filetype=m.buffer(chunk)
        break
    return filetype


##############################################################################
# Metadata Extraction
##############################################################################

def get_trid(fpath):
    # Call TRiD - location set in settings.py
    run = subprocess.Popen([trid_loc, fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    trid_res = run.communicate()[0].strip()

    return unicode(trid_res, 'utf-8', errors="replace")

def get_exif(fpath):

    with exiftool.ExifTool() as et:
        metadata = et.execute(fpath)

    return unicode(metadata, 'utf-8', errors="replace")    

##############################################################################
# Strings Analysis
##############################################################################

def get_strings(fpath):

    string_res = "ASCII Strings:\r\n\r\n"

    run = subprocess.Popen(["strings",fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    string_res += run.communicate()[0]
    string_res += "\r\nUNICODE Strings:\r\n\r\n"

    run = subprocess.Popen(["strings","-e","l",fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    string_res += run.communicate()[0]

    return unicode(string_res, 'utf-8', errors="replace")
    
def get_balbuzard(fpath):
    # Call Balbuzard.py - location set in settings.py
    run = subprocess.Popen([sys.executable, balbuzard_loc, fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    balbuzard_output = run.communicate()[0]

    output = []
    header_complete = False
    # Balbuzard uses 79 '=' to indicate the beginning of the analysis
    header_mark = "="*79 
    for line in balbuzard_output.split('\n'):
        if line == header_mark:
            header_complete = True
        elif header_complete:
            output.append(line)

    balbuzard_res = '\n'.join(output)
    
    return unicode(balbuzard_res, 'utf-8', errors="replace")


##############################################################################
# EXE data extraction 
##############################################################################

def get_peframe(fpath):
    # Call peframe (only if executable file detected from python-magic)
    run = subprocess.Popen([peframe_loc,fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    peframe_res = run.communicate()[0]

    return unicode(peframe_res, 'utf-8', errors="replace")

def get_pescanner(fpath):
    # Call pescanner (only if EXE detected)
    run = subprocess.Popen([pescanner_loc, fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    pescanner_res = run.communicate()[0]

    return unicode(pescanner_res, 'utf-8', errors="replace")
    
##############################################################################
# PDF data extraction 
##############################################################################

def get_pdfid(fpath):
    # Call PDFiD (only if PDF detected)
    run = subprocess.Popen([pdfid_loc,fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    pdfid_res = run.communicate()[0]

    return unicode(pdfid_res, 'utf-8', errors="replace")


def get_peepdf(fpath):
    # Call PEEPDF (only if PDF detected)
    run = subprocess.Popen([peepdf_loc, "-g", fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    peepdf_res = run.communicate()[0]

    return unicode(peepdf_res, 'utf-8', errors="replace")
    

def get_pdfstrings(fpath):
    with open(fpath, 'rb') as fh:
        src_pdf_blob = fh.read()
        
    texts = []
    pdf = PyPDF2.PdfFileReader(StringIO.StringIO(src_pdf_blob))
    for page_num, page in enumerate(pdf.pages):
        texts.append(page.extractText())
    extracted_text = ("*"*80 + "\n").join(texts)
    
    return extracted_text.encode('utf-8', errors="replace")
    #return unicode(extracted_text, 'utf-8', errors="replace")
    
    
##############################################################################
# Document data extraction
##############################################################################

def get_oleid(fpath):
    # Call OLEID (only if Word Doc detected)
    run = subprocess.Popen([oleid_loc, fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    oleid_res = run.communicate()[0]

    return unicode(oleid_res, 'utf-8', errors="replace")

def get_olemeta(fpath):
    # Call OLEMETA (only if Word Doc and OLE identified)
    run = subprocess.Popen([olemeta_loc, fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    olemeta_res = run.communicate()[0]

    return unicode(olemeta_res, 'utf-8', errors="replace")

def get_olevba(fpath):
    # Call OLEVBA (only if Word Doc and VBA identified)
    run = subprocess.Popen([olevba_loc,"--decode",fpath],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    olevba_res = run.communicate()[0]

    return unicode(olevba_res, 'utf-8', errors="replace")

def rtf_iter_objects (fpath, min_size=32):
    # From decalage oletools rtfobj script

    PATTERN = r'(?:(?:[0-9A-Fa-f]{2})+\s*)*(?:[0-9A-Fa-f]{2}){4,}'
    TRANSTABLE_NOCHANGE = string.maketrans('', '')

    data = open(fpath, 'rb').read()
    for m in re.finditer(PATTERN, data):
        found = m.group(0)
        found = found.translate(TRANSTABLE_NOCHANGE, ' \t\r\n\f\v')
        if len(found)>min_size:
            yield m.start(), found

def get_rtfobj(fpath):
    # Call RTFOBJ (only if RTF doc identified)
    # Problem: Running like this causes the output to save
    # to the root 'wipster' directory, instead of the
    # appropriate subdirecotry for the sample.
    '''
    run = subprocess.Popen([rtfobj_loc,f.name],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE)

    rtfobj_res = run.communicate()[0]

    return rtfobj_res
    '''

    # Code modified from decalage oletools rtfobj script to
    # save in the appropriate directory
    rtfobj_res = ''
    rtflist = []
    rtf_objects = rtf_iter_objects(fpath)
    if rtf_objects:
        for index, data in rtf_iter_objects(fpath):
            rtfobj_res += 'found object size %d at index %08X \r\n' % (len(data), index)
            fname, junk = os.path.split(f.name)
            fname += '/object_%08X.bin' % index
            rtflist.append(fname)
    #        rtfobj_res += 'saving to file %s \r\n' %fname
            linkname = fname.split('/', 1)
            rtfobj_res += "saving to file <a href='/{0}'>{1}</a>\r\n".format(linkname[1],fname)
            open(fname, 'wb').write(data)

        #return unicode(rtfobj_res, 'utf-8', errors="replace"), unicode(rtflist, 'utf-8', errors="replace")
    else:
        rtfobj_res += "No RTF Objects Found."
    return unicode(rtfobj_res, 'utf-8', errors="replace"), rtflist

def get_rtfobj_str(rtflist):

    rtfobj_str_res = "#### ASCII ####\r\n"

    for fpath in rtflist:
        run = subprocess.Popen(["strings", fpath],
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE)

        rtfobj_str_res += run.communicate()[0]

    rtfobj_str_res = "\r\n#### UNICODE #### \r\n"
    for fpath in rtflist:
        run = subprocess.Popen(["strings", "-e", "l", fpath],
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE)

        rtfobj_str_res += run.communicate()[0]

    return unicode(rtfobj_str_res, 'utf-8', errors="replace")
    
##############################################################################
# External analysis tools
##############################################################################

def get_virustotal(md5):
    #Query VirusTotal for a given MD5
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5,
                  "apikey": vt_key}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    vt_res = ""
    vt_short_res = ""

    if vt_use:
        response = urllib2.urlopen(req)
        json_resp = response.read().decode('utf-8')
        try:
            vt_resp = json.loads(json_resp)
        except ValueError, e:
            vt_resp['response_code']='No JSON response - likely hit VT API rate limit.'
        if vt_resp['response_code'] or vt_resp['response_code']==0:
            if vt_resp['response_code']==1:

                #handle json - return long list and short list
                #  for k, v in vt_resp.iteritems():
                text_results = "Results:\t"+str(vt_resp['positives'])+"/"+str(vt_resp['total'])+"\r\n"
                vt_res += text_results
                vt_short_res += text_results
                text_results = "Scan Date:\t"+vt_resp['scan_date']+"\r\n"
                vt_res += text_results
                vt_short_res += text_results
                vt_res += "Permalink:\t"+vt_resp['permalink']+"\r\n\r\n"
                vt_short_res += "<a href='"+vt_resp['permalink']+"' target='_blank'>"
                vt_short_res += vt_resp['permalink']+"</a>\r\n\r\n"
                for vendor, details in vt_resp['scans'].iteritems():
                    spaces = (25 - len(vendor))*" "
                    vt_res += str(vendor)+":"+spaces+str(details['result'])+"\r\n"
                    if vendor in vt_short:
                        vt_short_res += str(vendor)+":\t"+str(details['result'])+"\r\n"
                
            elif vt_resp['response_code']==0:
                vt_res += "No VirusTotal Results Found."
                vt_short_res += vt_res
            else:
                vt_res += "Something went wrong. Response Code: "+str(vt_resp['reponse_code'])
                vt_short_res += vt_res
        else:
            vt_res += "No response code received from VirusTotal. Something is horribly wrong.\r\n"
            vt_res += str(vt_resp)
            vt_short_res += vt_res

    return vt_res, vt_short_res
    
    


    

