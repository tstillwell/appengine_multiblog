function show_edit(comment_id){
  var comment_classname = 'comment-' + comment_id;
  var old_comment = $('.comment-' + comment_id).html();
  $("." + comment_classname).replaceWith(
      '<div class="comment comment-' + comment_id + '">' + old_comment +
      '<div class="edit_area"><textarea id="new_comment_field_' + comment_id + '">' +
      '</textarea><br>' + '<button onclick="edit_comment(' + comment_id + ')">' +
      'Update Comment' + '</button><button onclick="cancel_edit(' + comment_id +
    ')"> Cancel</button></div></div>'
  );
  $(".edit_button").hide();
  $('form[name=comment-form]').hide();
}
function cancel_edit(comment_id){
  $(".edit_area").remove();
  $(".edit_button").show();
  $('form[name=comment-form]').show();
}
function new_comment_text(comment_id){
  return document.getElementById('new_comment_field_' + comment_id).value;
}
function edit_comment(comment_id){
  $.ajax({
    dataType: 'json',
    url: "/commentajax/",
    type: "POST",
    data: JSON.stringify({"comment_id": comment_id,
                          "new_text": new_comment_text(comment_id)})
  })
  .done(function( response ) {
    var comment_class = 'comment-content-' + comment_id;
    var newdiv = '<div class=' + '"' + comment_class + '"' + '>';
    $('.' + comment_class).replaceWith(newdiv + response['new_text'] + '</div>');
    $(".edit_area").remove();
    $('form[name=comment-form]').show();
    $(".edit_button").show();
  });
};
