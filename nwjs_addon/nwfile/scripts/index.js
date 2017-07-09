try {
    window.allow_file_operation = true;

    var addon = require("./addon");
	var AES_data = addon.AES_data;
    var addRoundKey_computing = addon.addRoundKey_computing;
    var shiftRows_computing = addon.shiftRows_computing;
    var mixColumns_computing = addon.mixColumns_computing;
    var subBytes_computing = addon.subBytes_computing;
    var file_operation = addon.file_operation;

	var data_key_DOM = document.querySelector("#data-key");
	var data_input_DOM = document.querySelector("#data-input");
	var data_output_DOM = document.querySelector("#data-output");
	var keys_container = document.querySelectorAll("#keys-container div");
	var states_container = document.querySelectorAll("#state-container div");

    $(document).bind("input", ".input-data", function (e) {
        e.target.value = e.target.value.replace(/ /g, "");
    });

    document.querySelector("#data-encrypt-btn").addEventListener("click", function() {
		if ($(this).hasClass("disabled")) {
		    return false;
        }

		var key = data_key_DOM.value;
		var input = data_input_DOM.value;
		var ouput = AES_data("-en", key, input);
		//alert(output);
		data_output_DOM.value = ouput.cipher_text;

		var keys = ouput.words;
		for (var i in keys) {
			keys_container[i].innerText = keys[i];
		}

		var states = ouput.states;
		for (var i in states) {
			states_container[i].innerText = states[i];
		}
	});

    document.querySelector("#data-decrypt-btn").addEventListener("click", function() {
        if ($(this).hasClass("disabled")) {
            return false;
        }

        var key = data_key_DOM.value;
        var input = data_input_DOM.value;
        var ouput = AES_data("-dn", key, input);
        //alert(output);
        data_output_DOM.value = ouput.cipher_text;

        var keys = ouput.words;
        for (var i in keys) {
            keys_container[i].innerText = keys[i];
        }

        var states = ouput.states;
        for (var i in states) {
            states_container[i].innerText = states[i];
        }
    });

	document.querySelector("#AddRoundKey-form").addEventListener("submit", function (e) {
        if ($("button", this).hasClass("disabled")) {
            return false;
        }

        e.preventDefault();
	    this.result.value = addRoundKey_computing(this.in.value, this.K.value);
    });

	document.querySelector("#ShiftRows-form").addEventListener("submit", function (e) {
	    if ($("button", this).hasClass("disabled")) {
            return false;
        }
	    e.preventDefault();
	    this.result.value = shiftRows_computing(this.in.value);
    });

	document.querySelector("#MixColumns-form").addEventListener("submit", function (e) {
	    if ($("button", this).hasClass("disabled")) {
            return false;
        }
	    e.preventDefault();
	    this.result.value = mixColumns_computing(this.in.value);
    });

	document.querySelector("#SubBytes-form").addEventListener("submit", function (e) {
	    if ($("button", this).hasClass("disabled")) {
            return false;
        }
	    e.preventDefault();
	    this.result.value = subBytes_computing(this.in.value);
    });


	var open_path_DOM = document.querySelector("#open-path");
    var save_path_DOM = document.querySelector("#save-path");

    open_path_DOM.addEventListener("input", function () {
        $('#open-file').val("");
    });
    save_path_DOM.addEventListener("input", function () {
        $('#save-file').val("");
    });

    document.querySelector("#open-btn").addEventListener("click", function () {
        var chooser = $('#open-file');
        chooser.unbind('change');
        chooser.change(function(evt) {
            if (!$(this).val()) return;
            open_path_DOM.value = $(this).val();
        });

        chooser.trigger('click');
    });

    document.querySelector("#save-btn").addEventListener("click", function () {
        var chooser = $('#save-file');
        chooser.unbind('change');
        chooser.change(function(evt) {
            if (!$(this).val()) return;
            save_path_DOM.value = $(this).val();
        });

        chooser.trigger('click');
    });

    var file_key_DOM = document.querySelector("#file-key");
    document.querySelector("#file-encrypt-btn").addEventListener("click", function() {
        if ( !window.allow_file_operation || $(this).hasClass("disabled") ) {
            return false;
        }
        window.allow_file_operation = false;
        file_operation("-ef", file_key_DOM.value,  open_path_DOM.value, save_path_DOM.value, function (e) {
            if (e === "") {
                alert("Encryption finished");
            } else {
                alert(e);
            }
            window.allow_file_operation = true;
        });
    });
    document.querySelector("#file-decrypt-btn").addEventListener("click", function() {
        if ( !window.allow_file_operation || $(this).hasClass("disabled") ) {
            return false;
        }
        window.allow_file_operation = false;
        file_operation("-df", file_key_DOM.value,  open_path_DOM.value, save_path_DOM.value, function (e) {
            if (e === "") {
                alert("Decryption finished");
            } else {
                alert(e);
            }
            window.allow_file_operation = true;
        });
    });


} catch (e) {
	document.write(e);
}
	//alert("Exception happened when loading core.");
