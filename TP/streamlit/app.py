import pickle
import pefile
import streamlit as st
import numpy as np


# loading in the model to predict on the data
pickle_in = open('model_pickle', 'rb')
classifier = pickle.load(pickle_in)


def welcome():
    return 'welcome all'


# defining the function which will make the prediction using
# the data which the user inputs
def prediction(charac):
    entry_array = np.array(charac).reshape(1, -1)
    final_prediction = classifier.predict(entry_array)
    return final_prediction


def extract_pe_characteristics(file_obj):
    file_bytes = file_obj.read()

    # Load the PE file
    pe = pefile.PE(data=file_bytes)

    # Extract the characteristics
    characteristics = {
        "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
        "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
        "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "NumberOfSections": len(pe.sections),  # Count of sections in the file
        "ResourceSize": 0  # Placeholder for Resource Size
    }

    # Extract the resource size if available
    try:
        resource_directory = pe.DIRECTORY_ENTRY_RESOURCE
        characteristics["ResourceSize"] = resource_directory.struct.Size
    except AttributeError:
        characteristics["ResourceSize"] = 0  # If no resource directory, set to 0

    # Close the PE file
    pe.close()

    return list(characteristics.values())

# this is the main function in which we define our webpage
def main():
    # giving the webpage a title
    st.title("Malware Prediction")

    # here we define some of the front end elements of the web page like
    # the font and background color, the padding and the text to be displayed
    html_temp = """ 
	<div style ="background-color:yellow;padding:13px"> 
	<h1 style ="color:black;text-align:center;">Malware Detection Classifier ML App </h1> 
	</div> 
	"""

    # this line allows us to display the front end aspects we have
    # defined in the above code
    st.markdown(html_temp, unsafe_allow_html=True)

    # the following lines create text boxes in which the user can enter
    # the data required to make the prediction

    exe_file = st.file_uploader("Choose an .exe file", type="exe")

    result = ""

    # the below line ensures that when the button called 'Predict' is clicked,
    # the prediction function defined above is called to make the prediction
    # and store it in the variable result
    if st.button("Predict"):
        file_charac = extract_pe_characteristics(exe_file)
        result = prediction(file_charac)
        # print(f"---result---\n{result[0]}")
        if result[0] == 1:
            st.error('this file is a MALWARE !!! '.format(result))
        else:
            st.success('this file is SAFE !!!'.format(result))


if __name__ == '__main__':
    main()
