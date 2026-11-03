<template>
  <div class="comment-list">
    <article v-for="c in comments" :key="c.id" class="comment">
      <h4>{{ c.author }}</h4>
      <div v-html="c.content"></div>
    </article>

    <a :href="redirectUrl" class="more">继续浏览</a>
    <div id="stat-slot"></div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from 'axios'

const comments = ref([])
const redirectUrl = ref('')

const token = localStorage.getItem('access_token')

onMounted(async () => {
  const { data } = await axios.get('/api/comments', {
    headers: { Authorization: 'Bearer ' + token }
  })
  comments.value = data

  const params = new URLSearchParams(location.search)
  redirectUrl.value = params.get('next')
  document.getElementById('stat-slot').innerHTML = params.get('msg')
})
</script>

<!--
  演示用样本：故意写坏的前端组件。
  预置问题：存储型 XSS（v-html）、Token 存 localStorage、开放重定向、innerHTML 注入。
-->
