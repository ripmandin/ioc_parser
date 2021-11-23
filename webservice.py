from flask import Flask, request, render_template, send_from_directory, abort, redirect, url_for, flash
import  os, re
import dfir_file_creator


app = Flask(__name__)
ALLOWED_EXTENSIONS = 'yml'
DOWNLOAD_FOLDER = os.getcwd()
app.config['SECRET_KEY'] = '!Vdys7qalBcbjyls#'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_url(url):
    if re.match(r'^https://thedfirreport.com[/\w .-]*/$', url, re.I):
        return url
    else:
        return False


@app.route("/", methods=['GET', 'POST'])
def url_form():
    return render_template("index.html")


@app.route("/verify", methods=['POST'])
def verify():
    if request.method == 'POST' and allowed_url(request.form['url']):
        return redirect(url_for('report'), code=307)
    else:
        flash('Invalid uri', category='error')
        return redirect(url_for('url_form'))


@app.route('/report', methods=['POST'])
def report():
    url = request.form['url']
    dfir_file_creator.docs_create(url)
    filename = url.split('/')[-2] + f'.{ALLOWED_EXTENSIONS}'
    return render_template('report.html', report_url=url, filename=filename)


@app.route('/download/<path:file>', methods=['GET', 'POST'])
def download(file=None):
    if allowed_file(file):
        return send_from_directory(DOWNLOAD_FOLDER, file)
    else:
        abort(404)


if __name__ == "__main__":
    app.run(debug=True, port=3333)
