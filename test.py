
import os
 
def record():
 
	audio = "Microphone (Realtek High Definition Audio)"
	video_size = "1920x1080"
 
	os.system(f"""ffmpeg -y -framerate 30 -rtbufsize 200M -f gdigrab -thread_queue_size 1024 -probesize 25M -r 10 -draw_mouse 1 -video_size {video_size} -i desktop -f dshow -channel_layout stereo -thread_queue_size 1024 -i audio="{audio}" -c:v mpeg4 -r 10 -preset ultrafast -tune zerolatency -crf 25 -pix_fmt yuv420p -c:a aac -strict -2 -ac 1 -b:a 48k -vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" -af "highpass=f=200, lowpass=f=3000, volume=100" -b:a 192k "D:\\Python\\Password\\video.avi" """)
 
 
record()