/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
import '../css/bootstrap.min.css'
import '../css/site.css'
import run from './top.js'
import package from '../../package.json'

var jquery = require('./jquery-1.10.2.min.js')
window.$ = window.jQuery = jquery
window.package = package

class Warper {

  constructor() {
    this.check_compatibility();
    this.attach_ux();
    if (window.SALT_DEFAULT != null) {
      $('#salt').val(window.SALT_DEFAULT);
      $('#salt').attr('disabled', true);
      $('.salt-label').text('Prefilled salt');
    }
  }

  check_compatibility() {
    if ((typeof Int32Array === 'undefined' || Int32Array === null)) {
      $('.form-container').html(`\
<p>
  Sorry, but your browser is too old to run WarpWallet, which requires Int32Array support.
</p>`
      );
    }
  }

  escape_user_content(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/\'/g, '&#39;'); }

  attach_ux() {
    $('#btn-submit').on('click',            () => this.click_submit());
    $('#btn-reset').on('click',             () => this.click_reset());
    $('#salt').on('change',                 () => this.salt_change());
    $('#salt').on('keyup',                  () => this.salt_change());
    $('#checkbox-salt-confirm').on('click', () => this.any_change());
    $('#passphrase').on('change',           () => this.any_change());
    $('#passphrase').on('keyup',            () => this.any_change());
    $('#public-address').on('click',        $(this).select());
    $('#private-key').on('click',           $(this).select());
    $('.what-salt').on('click',             () => $('.salt-explanation').toggle());
  }

  any_change() {
    $('.progress-form').hide();
    $('#private-key').val('');
    $('#public-address').val('');
    $('#btn-submit').attr('disabled', false).show().html('Generate');
    const pp   = $('#passphrase').val();
    const salt = $('#salt').val();
    const chk  = $('#checkbox-salt-confirm').is(":checked");
    let err  = null;
    let warn = null;
    if (!pp.length) {
      err = "Please enter a passphrase";
    } else if ((salt != null ? salt.length : undefined) && !this.salt_ok()) {
      err = "Fix your salt";
    } else if ((salt != null ? salt.length : undefined) && (!chk) && ((window.SALT_DEFAULT == null))) {
      err = "Confirm your salt";
    } else if (pp.length < 12) {
      warn = "Consider a larger passphrase";
    }

    if (err) {
      $('#btn-submit').attr('disabled', true).html(err);
    } else if (warn) {
      $('#btn-submit').attr('disabled', false).html(warn);
    } else {
      $('#btn-submit').attr('disabled', false).html("Generate");
    }
    $('.output-form').hide();
    $('#public-address-qr').html('');
    $('#private-key-qr').html('');
  }

  commas(n) {
    while (/(\d+)(\d{3})/.test(n.toString())) {
      n = n.toString().replace(/(\d+)(\d{3})/, '$1,$2');
    }
    return n;
  }

  salt_ok() {
    const salt = $('#salt').val();
    return (salt.match(/^[\S]+@[\S]+\.[\S]+$/)) || (window.SALT_DEFAULT != null);
  }

  salt_change() {
    const salt = $('#salt').val();
    console.log(salt)
    $('#checkbox-salt-confirm').attr('checked', false);
    if (!salt.length) {
      $('.salt-confirm').hide();
    }
    if (window.SALT_DEFAULT != null) {
      $('.salt-confirm').hide();
    } else if (this.salt_ok()) {
      $('.salt-confirm').show();
      $('.salt-summary').html(this.escape_user_content(salt));
    } else {
      $('.salt-confirm').hide();
    }
    this.any_change();
  }

  progress_hook(o) {
    let w;
    if (o.what === 'scrypt') {
      w = (o.i / o.total) * 50;
      $('.progress-form .bar').css('width', `${w}%`);
      $('.progress-form .bar .progress-scrypt').html(`scrypt ${this.commas(o.i)} of ${this.commas(o.total)}`);

    } else if (o.what === 'pbkdf2') {
      w = 50 + ((o.i / o.total) * 50);
      $('.progress-form .bar').css('width', `${w}%`);
      $('.progress-form .bar .progress-pbkdf2').html(`&nbsp; pbkdf2 ${this.commas(o.i)} of ${this.commas(o.total)}`);
    }
  }

  click_reset() {
    $('#btn-submit').attr('disabled', false).show().html('Please enter a passphrase');
    $('#passphrase, #public-address, #private-key').val('');
    if ((window.SALT_DEFAULT == null)) {
      $('#salt').val('');
    }
    $('#checkbox-salt-confirm').attr('checked', false);
    $('.salt-summary').html('');
    $('.salt-confirm').hide();
    $('.progress-form').hide();
    $('.output-form').hide();
    $('#public-address-qr').html('');
    $('#private-key-qr').html('');
  }

  write_qrs(pub, priv) {
    const params = {
      width:        256,
      height:       256,
      colorLight:   "#f8f8f4",
      correctLevel: QRCode.CorrectLevel.H
    };
    (new QRCode("public-address-qr", params)).makeCode(pub);
    (new QRCode("private-key-qr", params)).makeCode(priv);
  }

  click_submit() {
    $('#btn-submit').attr('disabled', true).html('Running...');
    $('#btn-reset').attr('disabled', true).html('Running...');
    $('#passphrase, #salt, checkbox-salt-confirm').attr('disabled', true);
    $('.progress-pbkdf2, .progress-scrypt').html('');
    $('.progress-form').show();

    run({
      passphrase : $('#passphrase').val(),
      salt : $('#salt').val(),
      progress_hook : o => this.progress_hook(o),
      params : window.params
    }, res => {

      $('#passphrase, #checkbox-salt-confirm').attr('disabled', false);
      if ((window.SALT_DEFAULT == null)) {
        $('#salt').attr('disabled', false);
      }
      $('.progress-form').hide();
      $('.output-form').show();
      $('#btn-submit').hide();
      $('#btn-reset').attr('disabled', false).html('Clear &amp; reset');
      $('#public-address').val(res.address);
      $('#private-key').val(res.secret);
      this.write_qrs(res.address, res.secret);
    });
  }
}

$(() => new Warper());
