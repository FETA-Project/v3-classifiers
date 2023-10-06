# FETA-V3

Demonstrator of V3 results of project FETA VJ02010024 granted by Ministry of Interior of Czech Republic. 


## Included classifiers

* SSH Classifier

The classifiers are located in `./bin/`. Each root folder of the classifier contains `provision.sh` script that is automatically called in the VM intialization. 

### Sample data
Demonstration data for each classifier are located in `./bin/%CLASSIFIER_ROOT%/sample_data`. You can look at the data using nemea logger. `/usr/bin/nemea/logger -t -i "f:%PATH_TO_DATA%"`

### Run the classifiers
The run scripts are placed into the $HOME directory. The scripts automatically use sample data from the classifier and place the results back to the current working directory. 




