async function scan() {
  let url = document.getElementById("url").value;
  let res = await fetch("/scan?url="+encodeURIComponent(url));
  document.getElementById("output").textContent = await res.text();
}
