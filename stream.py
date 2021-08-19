import numpy as np
from cv2 import VideoWriter_fourcc, VideoWriter, VideoCapture, imshow, waitKey, destroyAllWindows, flip, CAP_PROP_FRAME_HEIGHT, CAP_PROP_FRAME_WIDTH

cap = VideoCapture(0)
cap.set(CAP_PROP_FRAME_WIDTH, 640)
cap.set(CAP_PROP_FRAME_HEIGHT, 480)

if (cap.isOpened()==False) :
        print("error in opening  video stream")
        exit()

fourcc = VideoWriter_fourcc('M','J','P','G')
out = VideoWriter('video.avi',fourcc,16,(640,480)) 

while(cap.isOpened()):
    
    ret,frame = cap.read()
    if ret == True:
            frame = flip(frame,1)
            out.write(frame)
            imshow('frame',frame)
            # Press 'q' to quit
            if waitKey(25) & 0xFF == ord('q'):
                break
    else:
        break
cap.release()
out.release()
destroyAllWindows()