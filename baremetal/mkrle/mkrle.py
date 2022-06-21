import sys
import logging
import time
import datetime
import re
import signal

import numpy as np
import struct
import gi
gi.require_version('Gst', '1.0')
gi.require_version('GstApp', '1.0')
gi.require_version('GstBase', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GstApp, GstBase, GstVideo, GLib, GObject

from gst_hacks import map_gst_buffer

Gst.init(sys.argv)

logger = logging.getLogger(__name__)

        

class GstOverlayGPS(GstBase.BaseSink):
    __gstmetadata__ = ("GPS overlay object",
                       "video.py",
                       "GPS overlay",
                       "jwise")
    __gsttemplates__ = (Gst.PadTemplate.new("sink",
                                            Gst.PadDirection.SINK,
                                            Gst.PadPresence.ALWAYS,
                                            Gst.Caps.from_string("video/x-raw,format=BGRA")))

    def __init__(self, f):
        super(GstOverlayGPS, self).__init__()
        self.last_tm = time.time()
        self.f = f
        self.frames_processed = 0
        self.bigframe = 0

    def do_render(self, buffer):
        tst = time.time()
        caps = self.sinkpad.get_current_caps()
        h = caps.get_structure(0).get_value("height")
        w = caps.get_structure(0).get_value("width")

        with map_gst_buffer(buffer, Gst.MapFlags.READ) as data:
            arr = np.asarray(data, dtype = np.uint8).reshape((w, h, 4, ))
            val = arr[::-1, ::-1, 0]
            thresh = val > 128
            thresh = thresh.reshape((w*h, ))
            
            # https://stackoverflow.com/questions/1066758/find-length-of-sequences-of-identical-values-in-a-numpy-array-run-length-encodi
            y = thresh[1:] != thresh[:-1]
            i = np.append(np.where(y), len(thresh) - 1)
            z = np.diff(np.append(-1, i))
            p = np.cumsum(np.append(0, z))[:-1]
            
            groups = 0
            for v in z:
                while v > 65535:
                    groups += 2
                    v -= 65535
                groups += 1
            self.f.write(struct.pack("<HH", groups, 1 if thresh[0] else 0))
            for v in z:
                while v > 65535:
                    self.f.write(struct.pack("<HH", 65535, 0))
                    v -= 65535
                self.f.write(struct.pack("<H", v))
            flen = len(z) * 2 + 4
            if flen > self.bigframe:
                self.bigframe = flen
            #surf = cairo.ImageSurface.create_for_data(data, cairo.FORMAT_ARGB32, w, h)
            #ctx = cairo.Context(surf)
            #self.painter(ctx, self.video_start_time + self.segment.position / 1000000000)

        self.frames_processed += 1
#        if TRANSFORM_VERBOSE:
#            print(f"transform took {(time.time() - tst) * 1000:.1f}ms, {1 / (time.time() - self.last_tm):.1f} fps")
        self.last_tm = time.time()

        return Gst.FlowReturn.OK

class RenderIt:
    def __init__(self, filename, outfilename):
        self.filename = filename
        self.outfilename = outfilename

    def adddecoder(self, pipeline):
        def mkelt(eltype):
            elt = Gst.ElementFactory.make(eltype, None)
            assert elt
            pipeline.add(elt)
            return elt

        multiqueue_vpad = None
        multiqueue_apad = None

        filesrc = mkelt("filesrc")
        filesrc.set_property("location", self.filename)

        matroskademux = mkelt("matroskademux")
        filesrc.link(matroskademux)

        def qtdemux_pad_callback(qtdemux, pad):
            name = pad.get_name()
            print(f"{name} {pad}")
            if name == "video_0":
                pad.link(multiqueue_vpad)
            elif name == "audio_0":
                pad.link(multiqueue_apad)
            else:
                print(f"qtdemux unknown output pad {name}?")
        matroskademux.connect("pad-added", qtdemux_pad_callback) # will not fire until preroll

        multiqueue = mkelt("multiqueue")
        multiqueue_vpad = multiqueue.get_request_pad("sink_%u")
        multiqueue_apad = multiqueue.get_request_pad("sink_%u")
        # pads linked above

        # audio pipeline
        queuea0 = mkelt("queue")
        multiqueue.get_static_pad(f"src_{multiqueue_apad.get_name().split('_')[1]}").link(queuea0.get_static_pad("sink"))
        aout = queuea0

        # video pipeline
        avdec = mkelt("vp9dec")
        multiqueue.get_static_pad(f"src_{multiqueue_vpad.get_name().split('_')[1]}").link(avdec.get_static_pad("sink"))
            
        scaleout = mkelt("videoscale")
        avdec.link(scaleout)

        rateout = mkelt("videorate")
        scaleout.link(rateout)

        capsfilter = mkelt("capsfilter")
        capsfilter.set_property('caps', Gst.Caps.from_string(f"video/x-raw,width=480,height=272,framerate=23/1"))
        rateout.link(capsfilter)

        videoconvert_in = mkelt("videoconvert")
        capsfilter.link(videoconvert_in)
        vout = videoconvert_in

        queuev1 = mkelt("queue")
        queuev1.set_property("max-size-bytes", 100 * 1024 * 1024)
        avdec.link(queuev1)
        
        return (aout, vout)

    def render(self):
        pipeline = Gst.Pipeline.new("pipeline")

        (aout, vout) = self.adddecoder(pipeline)

        def mkelt(eltype):
            elt = Gst.ElementFactory.make(eltype, None)
            assert elt
            pipeline.add(elt)
            return elt

        gpsoverlay = GstOverlayGPS(open(self.outfilename, 'wb'))
        pipeline.add(gpsoverlay)
        #gpsoverlay = mkelt("autovideosink")
        vout.link(gpsoverlay)
        
        fakesink = mkelt("fakesink")
        fakesink.set_property("sync", False)
        aout.link(fakesink)

        pipeline.use_clock(None)

        loop = GLib.MainLoop()
        def on_message(bus, message):
            mtype = message.type
            if mtype == Gst.MessageType.STATE_CHANGED:
                pass
            elif mtype == Gst.MessageType.EOS:
                print("\nEOS")
                pipeline.set_state(Gst.State.NULL)
                loop.quit()
            elif mtype == Gst.MessageType.ERROR:
                print("\nError!")
            elif mtype == Gst.MessageType.WARNING:
                print("\nWarning!")
            return True

        bus = pipeline.get_bus()
        bus.connect("message", on_message)
        bus.add_signal_watch()

        starttime = time.time()
        alldone = False
        def on_timer():
            if alldone:
                return False
            (_, pos) = pipeline.query_position(Gst.Format.TIME)
            (_, dur) = pipeline.query_duration(Gst.Format.TIME)
            now = time.time() - starttime
            if dur <= 1000 or now <= 1:
                print("starting up...", end='\r')
                return True
            now = datetime.timedelta(seconds = now)
            pos = datetime.timedelta(microseconds = pos / 1000)
            dur = datetime.timedelta(microseconds = dur / 1000)
            print(f"{pos / dur * 100:.1f}% ({pos/now:.2f}x realtime; {pos} / {dur}; {gpsoverlay.frames_processed} frames)", end='\r')
            return True
        GLib.timeout_add(200, on_timer)

        pipeline.set_state(Gst.State.PLAYING)

        def shutdown_loop(*args):
            pipeline.send_event(Gst.Event.new_eos())
            pipeline.set_state(Gst.State.NULL)
            loop.quit()

        try:
            signal.signal(signal.SIGINT, shutdown_loop)
            loop.run()
        except e:
            shutdown_loop()
            
        alldone = True
        print("")
        print(f"max frame size = {gpsoverlay.bigframe} bytes, {gpsoverlay.frames_processed} frames")

RenderIt("video.mkv", "video.rle").render()