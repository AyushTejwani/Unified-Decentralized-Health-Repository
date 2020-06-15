# -*- coding: utf-8 -*-
"""
Created on Fri Jan 24 14:23:38 2020

@author: Srivallabh
"""

from PIL import Image  
import pytesseract as pt
import os
def main():
    
   
    # path for the folder for getting the raw images 
    path =("E:\\Third Year\\EDD\\inputimgs")
    # link to the file in which output needs to be kept 
    tempPath =("E:\\Third Year\\EDD\\outputtexts")
    # iterating the images inside the folder 
    for imageName in os.listdir(path): 
              
        inputPath = os.path.join(path, imageName) 
        img = Image.open(inputPath) 
        pt.tesseract_cmd =("C:\\Program Files\\Tesseract-OCR\\tesseract.exe")
        # applying ocr using pytesseract for python 
        text = pt.image_to_string(img, lang ="eng") 
  
        fullTempPath = os.path.join(tempPath, 'time_'+imageName+".txt") 
        print(text) 
  
        # saving the  text for every image in a separate .txt file 
        file1 = open(fullTempPath, "w") 
        file1.write(text) 
        file1.close()  
  
if __name__ == '__main__': 
    main() 
