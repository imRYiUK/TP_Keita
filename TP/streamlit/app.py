import pickle
import pefile
import streamlit as st
import numpy as np


# loading in the model to predict on the data
pickle_in = open('/mount/src/tp_keita/TP/streamlit/model_pickle', 'rb')
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

def main():
    # Custom CSS for styling
    st.markdown(
        """
        <style>
        .main-title {
            background-color: #0047ab;
            padding: 20px;
            border-radius: 10px;
            color: white;
            text-align: center;
            font-size: 24px;
        }
        .section-title {
            color: #0047ab;
            font-size: 20px;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        .file-upload {
            text-align: center;
            margin-top: 20px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Main title
    st.markdown('<div class="main-title">Malware Detection Classifier ML App</div>', unsafe_allow_html=True)

    # Section title
    st.markdown('<div class="section-title">Upload an Executable File (.exe)</div>', unsafe_allow_html=True)

    # File uploader
    exe_file = st.file_uploader("", type="exe", label_visibility="collapsed")

    # Predict button and result
    if exe_file is not None:
        if st.button("Predict", use_container_width=True):
            file_charac = extract_pe_characteristics(exe_file)
            result = prediction(file_charac)

            # Display the result
            if result[0] == 1:
                st.error('⚠️ This file is a MALWARE!')
            else:
                st.success('✅ This file is SAFE!')

if __name__ == '__main__':
    main()
