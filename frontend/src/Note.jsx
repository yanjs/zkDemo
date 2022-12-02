const Note = (props) => {
  const { noteId, amt, nonce, isUsed } = props;
  return (
    <div className="border">
      <div>nonce = {nonce}</div>
      <div>isUsed = {isUsed.toString()}</div>
      <div>id = {noteId}</div>
      <div>amount = {parseInt(amt, 16)}</div>
    </div>
  );
};

export default Note;
