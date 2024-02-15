# **ICO and DLL Generator**

> A simple python script that scans the entire current working directory and create .ico files for all the available images.
> These .ico files are then bundled together into a dll file
> This dll file can now be used to change folder icons on windows desktop

--> I created these scripts because I wanted to make a "one piece" themed desktop for my computer and I have also included all the images I wanted to create a dll of in the repo.

## **Set up virtual enviornment**

1. Create virtual env: `python -m venv venv`
2. Activate env (on windows): `venv\Scripts\activate`
3. Install dependencies: `pip install --no-cache-dir -r requirements.txt`

## **Create executable file for the program**

Execute: `pyinstaller.exe --onefile --paths venv\Lib\site-packages .\Generate_dll_bundle_for_ico_images.py --name=Create-Ico-Dll-Bundle`

--> This will create two folder, inside the folder named "dist", there will be an exe named "Create-Ico-Dll-Bundle.exe"
--> Place this exe file in and folder and double click it, It will find all the images in that folder and create a file named "IconLib.dll"
--> You can use this dll file to change the icons of your folder

*** If you want to stop the executable from scanning some folder or images, create a new folder named "ScanBypass" and place all the folders or images inside it. This folder will not be scanned.
