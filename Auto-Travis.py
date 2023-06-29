#!/usr/bin/python3
import xlsxwriter
import pymysql
import os
from os import system
# TODO:
#This version has a bug when database schema for column nessus_host_id is not unique, it will add those IP's as findings incorrectly
# Add Enclave/Plane option
# Add Finding added by option
######## Settings ########
conn = pymysql.connect(host='localhost',user='nessusdb',password='nessusdb',database='nessusdb')
##########################

def list_scans():
    cur.execute("select name from scan")
    results = cur.fetchall()
    for result in results:
        print(result)
    input("***Press ENTER if all scans listed above are correct for findings report***")
    system('clear')

def get_findings_plugins():
    #Get unique pluginIDs (excluding informational)
    cur.execute("SELECT DISTINCT plugin_id from plugin where severity <> 0 ORDER by severity DESC")
    results = cur.fetchall()
    #print("DEBUG-Unique plugins that are not informational -->",result)
    return(results)

def get_findings_details(findings_plugins):
    cellcount = 0
    for findings_plugin in findings_plugins:
        cellcount = cellcount + 1
    ##### start pete's shitty function #####
    spreadsheetName = "SAR.for.travis.xlxs"
    spreadsheetloc = str(os.getcwd()) + "/" + spreadsheetName
    workbook = xlsxwriter.Workbook(spreadsheetloc)
    worksheet = workbook.add_worksheet()
    ### Create raw template ###
    # Full black cells:
    blackcell = workbook.add_format()
    blackcell.set_pattern(1)
    blackcell.set_bg_color('black')
    # Used for first row:
    arialbold = workbook.add_format()
    arialbold.set_font_name()
    arialbold.set_font_size(11)
    arialbold.set_bold(True)
    arialbold.set_align('bottom')
    arialbold.set_text_wrap()
    # Used for "Certifier Comments:" and "Recommendation:":
    normalBOLDtext = workbook.add_format()
    normalBOLDtext.set_font_name('Calibri')
    normalBOLDtext.set_font_size(11)
    normalBOLDtext.set_bold(True)
    normalBOLDtext.set_align('top')
    normalBOLDtext.set_align('left')
    normalBOLDtext.set_text_wrap()
    # Sets specific heights of columns (first line below is for ROW 1):
    worksheet.set_column('A:A', 10.86, arialbold)
    worksheet.set_column('B:B', 12.14, arialbold)
    # POAM ID was a wokey cell, made a specific setting for it:
    aCell = arialbold
    aCell.set_align('center')
    # Writing default items (POAM, IPs, etc):
    worksheet.write('A1', 'POA&M ID', aCell)
    worksheet.write('B1', 'IP(s)', arialbold)
    worksheet.set_column('C:C', 10.86, arialbold)
    worksheet.write('C1', 'Source /PluginID', arialbold)
    worksheet.set_column('D:D', 10.86, arialbold)
    worksheet.set_column('E:E', 44.86, arialbold)
    worksheet.write('D1', 'Risk Level', arialbold)
    worksheet.write('E1', 'Finding Name', arialbold)
    worksheet.set_column('F:F', 32.43, arialbold)
    worksheet.write('F1', 'Finding Details', arialbold)
    worksheet.set_column('G:G', 48.29, normaltext)
    worksheet.write('G1', 'Certifier Comments & Recommendation', arialbold)
    worksheet.set_column('I:I', 10.86, arialbold)
    worksheet.write('I1', 'Enclave/Plane', arialbold)
    worksheet.set_column('J:J', 22.86, arialbold)
    worksheet.write('J1', 'Fidning added by', arialbold)
    worksheet.set_column('K:K', 19.14, arialbold)
    worksheet.write('K1', 'Mitigated Onsite?', arialbold)
    # Black Cells
    worksheet.set_column('H:H', 5.14, arialbold)
    # testcount is used to count how many finding rows there are based on Chris's unique sort of plugins, so that it can append to the proper cell row
    testcount = 1
    for finding_plugin in findings_plugins:
        #This section fixes a bug when database schema for column nessus_host_id is not unique, it now works correctly
        cur.execute("select V.nessus_host_id, V.scan_run_id from host_vuln V where plugin_id =%s", (finding_plugin))        
        nss_unique_ids = cur.fetchall()
        ip_temp = ""
        ips = []
        for nss_unique_id in nss_unique_ids:
            cur.execute("select DISTINCT host_ip from host where nessus_host_id =%s and scan_run_id=%s", (finding_plugin))
            ip_temp = cur.fetchall()
            ips.append(ip_temp[0])
            #print("DEBUG-ips(growing)",ips,finding_plugin)
        cur.execute("select severity from plugin where plugin_id = %s", (finding_plugin))
        risk_level = cur.fetchall()
        num2severity = {1: 'low' , 2: 'medium', 3: 'high', 4: 'critical'}
        risk_level=num2severity[(risk_level[0])[0]]
        cur.execute("select name from plugin where plugin_id = %s", (finding_plugin))
        finding_name = ((cur.fetchall()[0])[0])
        cur.execute("select description from plugin where plugin_id = %s", (finding_plugin))
        finding_description = ((cur.fetchall()[0])[0])
        cur.execute("select solution from plugin where plugin_id = %s", (finding_plugin))
        finding_solution = ((cur.fetchall()[0])[0])
        testcount = testcount + 1
        worksheet.write('B' + str(testcount), "\n".join([str(line[0]) for line in ips]), normaltext)
        worksheet.write('C' + str(testcount), "Nessus PluginID="+str(finding_plugin[0]), normaltext)
        worksheet.write('D' + str(testcount), str(risk_level), normaltext)
        worksheet.write('E' + str(testcount), str(finding_name), normaltext)
        worksheet.write('F' + str(testcount), str(finding_description), normaltext)
        worksheet.write('G' + str(testcount), '', normaltext)
        worksheet.write_rich_string('G' + str(testcount), normalBOLDtext, 'Certifier Comments:', normaltext, "\nNone", normalBOLDtext, "\nRecommendation:\n", normaltext, str(finding_solution))
        worksheet.write('A' + str(testcount), '', blackcell)
        worksheet.write('H' + str(testcount), 5.14, blackcell)
    workbook.close()
    
################################

system('clear')
cur = conn.cursor()
print("All Scans within the MySQL database (imported w/ nessus_database_export)")
list_scans()
findings_plugins=get_findings_plugins()
get_findings_details(findings_plugins)
