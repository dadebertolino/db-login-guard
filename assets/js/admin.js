/**
 * DB Login Guard — Admin JS
 */
(function($) {
    'use strict';

    $(document).ready(function() {

        // Clear log
        $('#dblg-clear-log').on('click', function() {
            if (!confirm(dblg.confirm_clear)) {
                return;
            }

            var $btn = $(this);
            $btn.prop('disabled', true);

            $.post(dblg.ajax_url, {
                action: 'dblg_clear_log',
                nonce: dblg.nonce
            }, function(response) {
                if (response.success) {
                    location.reload();
                } else {
                    alert(response.data || 'Errore');
                    $btn.prop('disabled', false);
                }
            }).fail(function() {
                alert('Errore di connessione');
                $btn.prop('disabled', false);
            });
        });

        // Export CSV
        $('#dblg-export-log').on('click', function() {
            var $btn = $(this);
            $btn.prop('disabled', true);

            $.post(dblg.ajax_url, {
                action: 'dblg_export_log',
                nonce: dblg.nonce
            }, function(response) {
                if (response.success && response.data.csv) {
                    var blob = new Blob(['\uFEFF' + response.data.csv], {
                        type: 'text/csv;charset=utf-8;'
                    });
                    var link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = response.data.filename;
                    link.style.display = 'none';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }
                $btn.prop('disabled', false);
            }).fail(function() {
                alert('Errore di connessione');
                $btn.prop('disabled', false);
            });
        });

        // Handle unchecked checkboxes
        $('form').on('submit', function() {
            $(this).find('input[type=checkbox][name^="dblg_"]').each(function() {
                if (!this.checked) {
                    $(this).after(
                        '<input type="hidden" name="' + this.name + '" value="0">'
                    );
                }
            });
        });
    });

})(jQuery);
