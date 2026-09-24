const API_URL = "";


const fileInput =
    document.getElementById("fileInput");


const uploadButton =
    document.getElementById("uploadButton");


const refreshButton =
    document.getElementById("refreshButton");


const statusElement =
    document.getElementById("status");


const resultCard =
    document.getElementById("resultCard");


const fileNameElement =
    document.getElementById("fileName");


const fileHashElement =
    document.getElementById("fileHash");


const blockNumberElement =
    document.getElementById("blockNumber");


const previousHashElement =
    document.getElementById("previousHash");


const blockHashElement =
    document.getElementById("blockHash");


const blockchainContainer =
    document.getElementById(
        "blockchainContainer"
    );



/*
    Upload Answer Script
*/

uploadButton.addEventListener(
    "click",
    async () => {

        const file =
            fileInput.files[0];


        if (!file) {

            statusElement.innerText =
                "Please select an answer script first.";

            return;
        }


        statusElement.innerText =
            "Uploading answer script...";


        uploadButton.disabled = true;


        try {

            const formData =
                new FormData();


            formData.append(
                "file",
                file
            );


            const response =
                await fetch(
                    `${API_URL}/upload`,
                    {
                        method: "POST",
                        body: formData
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Upload failed."
                );

            }


            /*
                Display result
            */

            fileNameElement.innerText =
                data.file_name;


            fileHashElement.innerText =
                data.file_hash;


            blockNumberElement.innerText =
                data.block.index;


            previousHashElement.innerText =
                data.block.previous_hash;


            blockHashElement.innerText =
                data.block.hash;


            resultCard.classList.remove(
                "hidden"
            );


            statusElement.innerText =
                "Answer script registered successfully.";


            /*
                Refresh blockchain
            */

            loadBlockchain();

        }

        catch (error) {

            console.error(error);


            statusElement.innerText =
                "Error: " +
                error.message;

        }

        finally {

            uploadButton.disabled = false;

        }

    }
);



/*
    Verify Answer Script
*/

const verifyFileInput =
    document.getElementById(
        "verifyFileInput"
    );


const verifyButton =
    document.getElementById(
        "verifyButton"
    );


const verifyStatus =
    document.getElementById(
        "verifyStatus"
    );


const verificationResult =
    document.getElementById(
        "verificationResult"
    );


const verificationTitle =
    document.getElementById(
        "verificationTitle"
    );


const verifyFileName =
    document.getElementById(
        "verifyFileName"
    );


const verifyFileHash =
    document.getElementById(
        "verifyFileHash"
    );


const verifyBlockNumber =
    document.getElementById(
        "verifyBlockNumber"
    );


const registeredFileName =
    document.getElementById(
        "registeredFileName"
    );


verifyButton.addEventListener(
    "click",
    async () => {

        const file =
            verifyFileInput.files[0];


        if (!file) {

            verifyStatus.innerText =
                "Please select an answer script.";

            return;
        }


        verifyStatus.innerText =
            "Checking blockchain...";


        verifyButton.disabled = true;


        try {

            const formData =
                new FormData();


            formData.append(
                "file",
                file
            );


            const response =
                await fetch(
                    `${API_URL}/verify`,
                    {
                        method: "POST",
                        body: formData
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                throw new Error(
                    data.error ||
                    "Verification failed."
                );

            }


            verificationResult.classList.remove(
                "hidden"
            );


            verifyFileName.innerText =
                data.file_name;


            verifyFileHash.innerText =
                data.file_hash;


            if (data.verified) {

                verificationTitle.innerText =
                    "✓ ANSWER SCRIPT VERIFIED";

                verificationTitle.style.color =
                    "#15803d";


                verifyStatus.innerText =
                    "This exact file is registered on the blockchain.";


                verifyBlockNumber.innerText =
                    data.block.index;


                registeredFileName.innerText =
                    data.block.file_name;

            }

            else {

                verificationTitle.innerText =
                    "✗ ANSWER SCRIPT NOT VERIFIED";

                verificationTitle.style.color =
                    "#dc2626";


                verifyStatus.innerText =
                    "This file was not found in the blockchain.";


                verifyBlockNumber.innerText =
                    "Not registered";


                registeredFileName.innerText =
                    "Not found";

            }

        }

        catch (error) {

            console.error(error);


            verifyStatus.innerText =
                "Verification error: " +
                error.message;

        }

        finally {

            verifyButton.disabled = false;

        }

    }
);


/*
    Load Blockchain
*/

async function loadBlockchain() {

    blockchainContainer.innerHTML =
        "<p class='empty'>Loading blockchain...</p>";


    try {

        const response =
            await fetch(
                `${API_URL}/blockchain`
            );


        const blockchain =
            await response.json();


        blockchainContainer.innerHTML = "";


        if (
            blockchain.length === 0
        ) {

            blockchainContainer.innerHTML =
                "<p class='empty'>Blockchain is empty.</p>";

            return;

        }


        blockchain.forEach(
            block => {

                const blockElement =
                    document.createElement(
                        "div"
                    );


                blockElement.className =
                    "block";


                blockElement.innerHTML = `

                    <div class="block-title">
                        Block #${block.index}
                    </div>


                    <div class="block-row">

                        <strong>
                            File Name
                        </strong>

                        ${block.file_name}

                    </div>


                    <div class="block-row">

                        <strong>
                            File Hash
                        </strong>

                        <div class="hash">
                            ${block.file_hash}
                        </div>

                    </div>


                    <div class="block-row">

                        <strong>
                            Previous Block Hash
                        </strong>

                        <div class="hash">
                            ${block.previous_hash}
                        </div>

                    </div>


                    <div class="block-row">

                        <strong>
                            Block Hash
                        </strong>

                        <div class="hash">
                            ${block.hash}
                        </div>

                    </div>

                `;


                blockchainContainer.appendChild(
                    blockElement
                );

            }
        );

    }

    catch (error) {

        console.error(error);


        blockchainContainer.innerHTML = `

            <p class="empty">
                Could not connect to Python server.
            </p>

        `;

    }

}



/*
    Refresh button
*/

refreshButton.addEventListener(
    "click",
    loadBlockchain
);