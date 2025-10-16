from collections import defaultdict, OrderedDict
from functools import wraps
from glob import glob
from mimetypes import guess_type
from os import path, mkdir, remove
import tempfile
from urllib.parse import quote
from urllib.request import pathname2url

import exifread
import hmac
import json
import time
from sh import convert

import settings
import requests
from bottle import (
    Response,
    request,
    response,
    static_file,
    template,
    abort,
    HTTPResponse,
    route
)


def log(msg):
    if settings.DEBUG:
        print(msg)


def make_hdfs_path(coll, thumb, filename=""):
    """
    Build HDFS path for given collection, thumb/orig, and filename.
    """
    try:
        coll_dir = settings.COLLECTION_DIRS[coll]
    except KeyError:
        abort(404, f"Unknown collection: {coll!r}")

    subdir = settings.THUMB_DIR if thumb else settings.ORIG_DIR

    parts = [settings.BASE_DIR, coll_dir, subdir]
    if filename:
        parts.append(filename)

    hdfs_path = '/'.join(p.strip('/') for p in parts)
    # Ensure it starts with /
    if not hdfs_path.startswith('/'):
        hdfs_path = '/' + hdfs_path
    return hdfs_path


def is_hdfs_path_exists(hdfs_path):
    response = requests.get(
        f"http://{settings.BIIMS_API}/api/storage/exists?path={hdfs_path}"
    )
    return response.ok


def create_hdfs_dir(hdfs_dir):
    requests.post(
        f"http://{settings.BIIMS_API}/api/storage/mkdir/", data={"path": hdfs_dir}
    )


def stream_hdfs_file(hdfs_path):
    chunk_size = 1024
    response = requests.get(
        f"http://{settings.BIIMS_API}/api/storage/download?path={hdfs_path}",
        stream=True,
    )
    return response.iter_content(chunk_size=chunk_size)


def upload_to_hdfs(hdfs_path, file):
    requests.post(
        f"http://{settings.BIIMS_API}/api/storage/upload/",
        data={'path':hdfs_path},
        files=file
    )


def generate_token(timestamp, filename):
    """Generate the auth token for the given filename and timestamp.
    This is for comparing to the client submited token.
    """
    timestamp = str(timestamp)
    mac = hmac.new(settings.KEY.encode(), timestamp.encode() + filename.encode(), 'md5')
    return ':'.join((mac.hexdigest(), timestamp))


class TokenException(Exception):
    """Raised when an auth token is invalid for some reason."""
    pass


def get_timestamp():
    """Return an integer timestamp with one second resolution for
    the current moment.
    """
    return int(time.time())


def validate_token(token_in, filename):
    """Validate the input token for given filename using the secret key
    in settings. Checks that the token is within the time tolerance and
    is valid.
    """
    if settings.KEY is None:
        return
    if token_in == '':
        raise TokenException("Auth token is missing.")
    if ':' not in token_in:
        raise TokenException("Auth token is malformed.")

    mac_in, timestr = token_in.split(':')
    try:
        timestamp = int(timestr)
    except ValueError:
        raise TokenException("Auth token is malformed.")

    if settings.TIME_TOLERANCE is not None:
        current_time = get_timestamp()
        if not abs(current_time - timestamp) < settings.TIME_TOLERANCE:
            raise TokenException("Auth token timestamp out of range: %s vs %s" % (timestamp, current_time))

    if token_in != generate_token(timestamp, filename):
        raise TokenException("Auth token is invalid.")


def require_token(filename_param, always=False):
    """Decorate a view function to require an auth token to be present for access.

    filename_param defines the field in the request that contains the filename
    against which the token should validate.

    If REQUIRE_KEY_FOR_GET is False, validation will be skipped for GET and HEAD
    requests.

    Automatically adds the X-Timestamp header to responses to help clients stay
    syncronized.
    """

    def decorator(func):
        @include_timestamp
        @wraps(func)
        def wrapper(*args, **kwargs):
            if always or request.method not in ('GET', 'HEAD') or settings.REQUIRE_KEY_FOR_GET:
                params = request.forms if request.method == 'POST' else request.query
                try:
                    validate_token(params.token, params.get(filename_param))
                except TokenException as e:
                    response.content_type = 'text/plain; charset=utf-8'
                    response.status = 403
                    return response
            return func(*args, **kwargs)

        return wrapper

    return decorator


def include_timestamp(func):
    """Decorate a view function to include the X-Timestamp header to help clients
    maintain time syncronization.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        (result if isinstance(result, Response) else response) \
            .set_header('X-Timestamp', str(get_timestamp()))
        return result

    return wrapper


def allow_cross_origin(func):
    """Decorate a view function to allow cross domain access."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except HTTPResponse as r:
            r.set_header('Access-Control-Allow-Origin', '*')
            raise

        (result if isinstance(result, Response) else response) \
            .set_header('Access-Control-Allow-Origin', '*')
        return result

    return wrapper


def resolve_file():
    """Inspect the request object to determine the file being requested.
    If the request is for a thumbnail and it has not been generated, do
    so before returning.

    Returns the relative path to the requested file in HDFS.
    """
    thumb_p = (request.query['type'] == "T")
    collection = request.query.coll
    filename = request.query.filename

    scale = int(request.query.scale)
    mimetype, encoding = guess_type(filename)
    assert mimetype in settings.CAN_THUMBNAIL

    root, ext = path.splitext(filename)
    if mimetype in ('application/pdf', 'image/tiff'):
        # use PNG for PDF thumbnails
        ext = '.png'
    thumb_name = f"{root}_{scale}{ext}"

    orig_path = make_hdfs_path(collection, False, filename)
    thumb_path = make_hdfs_path(collection, True, thumb_name)

    if not thumb_p:
        return orig_path

    if is_hdfs_path_exists(thumb_path):
        log(f"Serving cached thumbnail: {thumb_path}")
        return thumb_path

    # To generate thumbnail, originals file is needed
    # Fetch original from HDFS first
    if not is_hdfs_path_exists(orig_path):
        abort(404, f"Missing original: {orig_path}")

    # Store original in local temp dir
    tmp = tempfile.gettempdir()
    local_orig = path.join(tmp, filename)
    local_thumb = path.join(tmp, thumb_name)

    with open(local_orig, 'wb') as f:
        for chunk in stream_hdfs_file(orig_path):
            f.write(chunk)

    input_spec = local_orig
    convert_args = ('-resize', f"{scale}x{scale}>")

    if mimetype == 'application/pdf':
        input_spec += '[0]'  # only thumbnail first page of PDF
        convert_args += ('-background', 'white', '-flatten')  # add white background to PDFs

    # Generate thumbnail locally then store in HDFS
    log(f"Scaling thumbnail to {scale}")
    convert(input_spec, *(convert_args + (local_thumb,)))

    thumb_dir = make_hdfs_path(collection, True)
    file = {'file': (local_thumb, open(local_thumb, "rb"))}
    if not is_hdfs_path_exists(thumb_dir):
        create_hdfs_dir(thumb_dir)

    upload_to_hdfs(thumb_path, file)

    # Clean up temp files
    remove(local_orig)
    remove(local_thumb)

    return thumb_path


@route('/static/<path:path>')
def static(path):
    """Serve static files to the client. Primarily for Web Portal."""
    if not settings.ALLOW_STATIC_FILE_ACCESS:
        abort(404)
    return static_file(path, root=settings.BASE_DIR)


@route('/getfileref')
@allow_cross_origin
def getfileref():
    """Returns a URL to the static file indicated by the query parameters."""
    if not settings.ALLOW_STATIC_FILE_ACCESS:
        abort(404)
    response.content_type = 'text/plain; charset=utf-8'
    return "http://%s:%d/static/%s" % (settings.HOST, settings.PORT,
                                       pathname2url(resolve_file()))


@route('/fileget')
@require_token('filename')
def fileget():
    """Returns the file data of the file indicated by the query parameters."""
    data = b''.join(stream_hdfs_file(resolve_file()))
    download_name = request.query.downloadname
    if download_name:
        download_name = quote(path.basename(download_name).encode('ascii', 'replace'))
        response.set_header('Content-Disposition', f"inline; filename*=utf-8''{download_name}")
    return data


@route('/fileupload', method='OPTIONS')
@allow_cross_origin
def fileupload_options():
    response.content_type = "text/plain; charset=utf-8"
    return ''


@route('/fileupload', method='POST')
@allow_cross_origin
@require_token('store')
def fileupload():
    """Accept original file uploads and store them in HDFS
    """
    thumb_p = (request.forms['type'] == "T")
    filename = request.forms.store
    collection = request.forms.coll
    hdfs_dir = make_hdfs_path(collection, thumb_p)
    store_path = make_hdfs_path(collection, thumb_p, filename)

    if thumb_p:
        return 'Ignoring thumbnail upload!'

    if not is_hdfs_path_exists(hdfs_dir):
        create_hdfs_dir(hdfs_dir)

    upload = list(request.files.values())[0]
    file = {'file': (filename, upload.file, upload.content_type)}
    
    upload_to_hdfs(store_path, file)

    response.content_type = 'text/plain; charset=utf-8'
    return 'Ok.'


@route('/filedelete', method='POST')
@require_token('filename')
def filedelete():
    """Delete the file indicated by the query parameters. Returns 404
    if the original file does not exist. Any associated thumbnails will
    also be deleted.
    """
    collection = request.forms.coll
    filename = request.forms.filename
    orig_path = make_hdfs_path(collection, False, filename)
    thumb_dir_path = make_hdfs_path(collection, True)

    if not is_hdfs_path_exists(orig_path):
        abort(404)

    log(f"Deleting {orig_path}")
    requests.post(
        f"http://{settings.BIIMS_API}/api/storage/delete/", data={"path": orig_path}
    )

    prefix = filename.split('.att')[0]
    thumb_dir = requests.get(f"http://{settings.BIIMS_API}/api/storage/list?path={thumb_dir_path}").json()

    for path_info in thumb_dir["data"]:
        if not path_info["is_file"]:
            continue
        if path_info["basename"].startswith(prefix):
            requests.post(
                f"http://{settings.BIIMS_API}/api/storage/delete/", data={"path": path_info["path"]}
            )

    response.content_type = 'text/plain; charset=utf-8'
    return 'Ok.'


@route('/getmetadata')
@require_token('filename')
def getmetadata():
    """Provides access to EXIF metadata."""
    storename = request.query.filename
    basepath = path.join(settings.BASE_DIR, get_rel_path(request.query.coll, thumb_p=False))
    pathname = path.join(basepath, storename)
    datatype = request.query.dt

    if not path.exists(pathname):
        abort(404)

    with open(pathname, 'rb') as f:
        try:
            tags = exifread.process_file(f)
        except:
            log("Error reading exif data.")
            tags = {}

    if datatype == 'date':
        try:
            return str(tags['EXIF DateTimeOriginal'])
        except KeyError:
            abort(404, 'DateTime not found in EXIF')

    data = defaultdict(dict)
    for key, value in list(tags.items()):
        parts = key.split()
        if len(parts) < 2: continue
        try:
            v = str(value).decode('ascii', 'replace').encode('utf-8')
        except TypeError:
            v = repr(value)

        data[parts[0]][parts[1]] = str(v)

    response.content_type = 'application/json'
    data = [OrderedDict((('Name', key), ('Fields', value)))
            for key, value in list(data.items())]

    return json.dumps(data, indent=4)


@route('/testkey')
@require_token('random', always=True)
def testkey():
    """If access to this resource succeeds, clients can conclude
    that they have a valid access key.
    """
    response.content_type = 'text/plain; charset=utf-8'
    return 'Ok.'


@route('/web_asset_store.xml')
@include_timestamp
def web_asset_store():
    """Serve an XML description of the URLs available here."""
    response.content_type = 'text/xml; charset=utf-8'
    return template('web_asset_store.xml', host="%s:%d" % (settings.SERVER_NAME, settings.SERVER_PORT))


@route('/')
def main_page():
    return 'It works!'


if __name__ == '__main__':
    from bottle import run
    run(
        host='0.0.0.0',
        port=settings.PORT,
        server=settings.SERVER,
        debug=settings.DEBUG,
        reloader=settings.DEBUG
    )
