#Import csv files
 $csv1 = Import-Csv ".\applications.csv"
 $csv2 = Import-Csv ".\endpoints.csv"
 
 #Compare the lists and add the Site column from endpoints.csv to applications.csv
 foreach ( $agent in $csv1 ) {
 
     #Set up object with properties we want
     $obj = "" | select "App Name","Endpoint Name","Site","Machine Type"
 
     #Find all matching 
     if ( $csv1.'Agent Name' -eq $csv2.'Endpoint Name' ) {

         #Confirm script is working
         Write-Host "Match found"

         #Set object properties
         $obj.'App Name' = $csv1.Name
         $obj.'Endpoint Name' = $csv1.'Agent Name'
         $obj.Site = $csv2.Site
         $obj.'Machine Type' = $csv1.'Machine Type'

         #Export the object into a new csv file
         $obj | Export-Csv -Path .\new_list.csv -Append -NoTypeInformation
     }
 }