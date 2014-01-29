#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <math.h>
#include <opencv/cv.h>
#include <opencv/highgui.h>
#include "opencv2/imgproc/imgproc.hpp"
#include "opencv2/objdetect/objdetect.hpp"
#include "opencv2/core/core.hpp"
#include "opencv2/highgui/highgui.hpp"

#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <libwebsockets.h>


int max_poll_elements;

struct pollfd *pollfds;
int *fd_lookup;
int count_pollfds;
int force_exit = 0;
int synchro=1;
time_t t=0;


enum demo_protocols {
	/* always first */
	PROTOCOL_HTTP = 0,

	PROTOCOL_DUMB_INCREMENT,


	/* always last */
	DEMO_PROTOCOL_COUNT
};

int getExecutablePath(char *path,uint32_t & size)
{
	size=readlink("/proc/self/exe",path,size);
	int i;
	for (i=size-1;path[i]!='/';i--) {
		//std::cerr<<i<<" "<<path[i]<<"\n";
	}
	path[i]=0;
	size=i+1;
	return size;
}

#define LOCAL_RESOURCE_PATH "/usr/share/libwebsockets-test-server"

/*
 * We take a strict whitelist approach to stop ../ attacks
 */

struct serveable {
	const char *urlpath;
	const char *mimetype;
};

static const struct serveable whitelist[] = {
	{ "/favicon.ico", "image/x-icon" },
	{ "/libwebsockets.org-logo.png", "image/png" },

	/* last one is the default served if no match */
	{ "/test.html", "text/html" },
};


struct per_session_data__dumb_increment {
	int number;
};

static int
callback_dumb_increment(struct libwebsocket_context *context,
                         struct libwebsocket *wsi,
                        enum libwebsocket_callback_reasons reason,
                        void *user, void *in, size_t len)
{



	struct per_session_data__dumb_increment *pss = (struct per_session_data__dumb_increment *)user;

	FILE *fich;
	char pathLect[1024];
	uint32_t size = sizeof(pathLect);
	//_NSGetExecutablePath(pathLect, &size);
	getExecutablePath(pathLect,size);
	int idInt = (int)t;
	char id[15];
	sprintf(id, "%d", idInt);
	strcat(pathLect, "/_logs/logLect_");
	strcat(pathLect, id);
	strcat(pathLect, ".txt");

	char pathDetect[1024];
	size = sizeof(pathDetect);
	//_NSGetExecutablePath(pathDetect, &size);
	getExecutablePath(pathDetect,size);
	strcat(pathDetect, "_logs/logDetect_");
	strcat(pathDetect, id);
	strcat(pathDetect, ".txt");




	switch (reason) {

        case LWS_CALLBACK_ESTABLISHED:
           pss->number = 0;
            break;




        case LWS_CALLBACK_RECEIVE:


            if (strcmp((const char *)in, "pause") == 0)
            {

                synchro=0;


            }
            else if (strcmp((const char *)in, "play") == 0)
            {

                synchro=1;
                if(t==0)
                {
                	t=time(&t);
                }

            }
           else if (strcmp((const char *)in, "do") == 0 || strcmp((const char *)in, "fin") == 0 )
            {

            	if(strcmp((const char *)in, "fin") == 0)
            	{
            		force_exit=1;
            	}

            	int n;
            	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +LWS_SEND_BUFFER_POST_PADDING];
            	unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];


            	int start=idInt;
            	time_t endT=time(&endT);
            	int end = (int) endT;
            	double intervalle=(end-start)/30;

            	printf("%s%f\n","intervalles 30sec :",intervalle);
            	if(intervalle>=1)
            	{
            		for(int a=0;a<(int)intervalle;a++)
            		{
						int vue=0;

						for(int i=0;i<30;i++)
						{



							fich= fopen(pathDetect,"r");
							char str[100];
							while(fgets(str,11,fich)!= NULL )
							{
									if(strlen(str)==10)
									{
										int cmp= atoi(str);
										if(cmp==idInt)
										{
											vue++;
											break;
										}
									}

							}
							fclose(fich);

							idInt++;
						}

						double pourcent=(vue*100)/30;

						n = sprintf((char *)p, "%d", (int)pourcent);
						libwebsocket_write(wsi, p, n, LWS_WRITE_TEXT);
						printf("%s%f%s\n","pourcentage : ",pourcent,"%");

            		}
				}
            	n = sprintf((char *)p, "%s", "end");
            	libwebsocket_write(wsi, p, n, LWS_WRITE_TEXT);


            }
            else
            {

            	fich= fopen(pathLect,"a");
            	char *message;
            	/*recup�ration du message de la variable in*/
            	message=(char *)in;
            	time_t tpsMess;
            	fprintf(fich,"%d",(int)time(&tpsMess));
            	fprintf(fich,"%s\n",message);
            	printf("%s",message);
            	fclose(fich);

           }


            break;


        default:
            break;
	}

	return 0;
}



/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */


	{
		"interact",
		callback_dumb_increment,
		sizeof(struct per_session_data__dumb_increment),
		100,
	},

	{ NULL, NULL, 0, 0 } /* terminator */
};

void sighandler(int sig)
{
	force_exit = 1;
}



using namespace cv;


/*    "haarcascade_profileface.xml";*/

double scale = 4;

CascadeClassifier cascade;


void detect_and_draw( Mat& image );


int main( int argc, char** argv )
{


	    struct libwebsocket_context *context;
	    int opts = 0;

	    const char *iface = NULL;
	    struct lws_context_creation_info info;

	    int debug_level = 7;
	    memset(&info, 0, sizeof info);
	    info.port = 7681;
	    signal(SIGINT, sighandler);

	    /* tell the library what debug level to emit and to send it to syslog */
	    lws_set_log_level(debug_level, lwsl_emit_syslog);
	    lwsl_notice("");
	    info.iface = iface;
	    info.protocols = protocols;
	    info.ssl_cert_filepath = NULL;
	    info.ssl_private_key_filepath = NULL;
	    info.gid = -1;
	    info.uid = -1;
	    info.options = opts;

	    context = libwebsocket_create_context(&info);
	    if (context == NULL) {
	        lwsl_err("libwebsocket init failed\n");
	        return -1;
	    }


	char path[1024];
	uint32_t size = sizeof(path);
	size=getExecutablePath(path,size);


	if (size==0)
	//if (_NSGetExecutablePath(path, &size) == 0)
	    printf("executable path is %s\n", path);
	else
	    printf("buffer too small; need size %u\n", size);

	sprintf(path,"%s/Reco.xml",path);
	printf("xml path is %s\n", path);

	 cv::Mat image ;


	    if (!cascade.load(path) )
	    {
	    	std::cerr<<"ERROR: Could not load classifier cascade\n" ;
	        return -1;
	    }

	    VideoCapture vc(0);
	    //VideoCapture vc("/home/mohamed/Bureau/_MARIUS/20130327_072523.mp4");


	    namedWindow( "result", 0 );

	   if (vc.isOpened()) {
		   std::cerr<<"open yes\n";
	        while(!force_exit)
	        {

	        	libwebsocket_service(context, 50);
	        	std::cerr<<"socket yes\n";
	        	if(synchro)
	        	{

						vc>>image;
						std::cerr<<"reading yes\n";
						detect_and_draw( image );
						std::cerr<<"drawing yes\n";
						if (waitKey(3)>=0) break;

	        	}
	        	else
	        	{
	        		cvDestroyWindow( "result" );

	        	}
	        }

	    }


    return 0;
}

void detect_and_draw( Mat &img )
{


    RNG rng(12345);

    cv::Mat gray, small_img;
    unsigned short i;

    gray.create(img.size(),1);

    cvtColor( img, gray, cv::COLOR_BGR2GRAY );
    resize(gray,small_img,Size(0,0),1./scale,1./scale);

    equalizeHist( small_img, small_img );

    std::vector<Rect> faces;

    Size minimumFaceSize=Size(50,50);
    cascade.detectMultiScale(small_img,faces,1.1,3,0,minimumFaceSize);

    std::cerr<<"detect faces done\n";

	char path[1024];
	uint32_t size = sizeof(path);
	size=getExecutablePath(path,size);
	int idInt = (int)t;

	char id[15];
	sprintf(id, "%d", idInt);
	strcat(path, "/_logs/logDetect_");
	strcat(path, id);
	strcat(path, ".txt");

	std::cerr<<"preparing to append to "<<path<<"\n";
	FILE *f;
	f = fopen(path,"a");
	//printf("%d \n",(int)t);

	for( i = 0; i < faces.size(); i++ )
    {

		Mat small_img_roi;
		std::vector<Rect> eyes;
		Rect r=faces[i];
		Point center;
		Scalar color = Scalar((uchar)rng,(uchar)rng,(uchar)rng);
		int radius;
		center.x = cvRound((r.x + r.width*0.5)*scale);
		center.y = cvRound((r.y + r.height*0.5)*scale);
		radius = cvRound((r.width + r.height)*0.25*scale);



		time_t tps;
		fprintf(f,"%d\n",(int)time(&tps));
		//fprintf(f,"Position x : %d,Position y : %d , longueur : %d, largeur : %d \n",r.x,r.y,r.width,r.height);
		circle( img, center, radius, color, 3, 8, 0 );

    }
    imshow( "result", img );
	fclose(f);

}
